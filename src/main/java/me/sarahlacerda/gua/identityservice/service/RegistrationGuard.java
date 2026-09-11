package me.sarahlacerda.gua.identityservice.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

/**
 * Beta-rollout gate that keeps an internet-exposed deployment from being used to
 * burn SMS credits or self-register open accounts, while leaving the beta
 * mobile apps and every returning user unaffected.
 *
 * <p>
 * It has two enforcement points, both driven by the SAME master switch
 * {@code idp.login.registration.web-allowlist-enabled} and both no-ops when it is
 * off, so the whole gate is a single flag flip away from the fully-open behaviour
 * (nothing here is baked into the normal code path):
 *
 * <ol>
 * <li><b>OTP send</b> ({@link #assertOtpAllowed}): the earliest point, before any
 * SMS is dispatched. A web flow may only trigger an OTP for a phone that is
 * already a known account or is explicitly allowlisted; an unknown web number is
 * refused with {@code 403 registration_not_approved} and no SMS is sent.</li>
 * <li><b>New-account creation</b> ({@link #assertAllowedForNewUser}): before the
 * account is provisioned, on both signup paths (the interactive
 * {@code /login/profile} step and the REST {@code /signup/complete}). A brand-new
 * web signup whose phone is not allowlisted is refused even if it obtained an OTP
 * some other way, for example through an exempt session.</li>
 * </ol>
 *
 * <p>
 * A phone is "known" when it already resolves to an account (directory digest, or
 * the homeserver phone binding as a pepper-drift fallback) OR is on the configured
 * allowlist. Because any account registered through the mobile apps lands in the
 * directory, an app-registered number is automatically recognised here and can log
 * in on the web with no extra plumbing.
 *
 * <p>
 * Web versus native comes from the {@code gua_downstream} marker MAS appends to the
 * upstream authorize request. That marker is a query parameter on a browser
 * redirect, so whoever drives the browser can edit it: the native exemption is a
 * convenience for the beta apps, not a security boundary. The gate therefore fails
 * closed. Only a marker exactly equal to the configured native marker is exempt; the
 * web marker, an absent or empty marker, and any unrecognised value are all treated
 * as web. Requests with no login session (the REST {@code /otp/send} and
 * {@code /signup/complete} endpoints) carry no marker and are always treated as web.
 */
@Component
@RequiredArgsConstructor
public class RegistrationGuard {

    private final LoginFlowProperties properties;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final MatrixAdminClient matrixAdminClient;

    /**
     * Rejects an OTP dispatch for a web flow whose phone is neither a known account
     * nor allowlisted. No-op when the gate is disabled or the session carries the
     * exact native marker. Called before the SMS is sent, so a blocked number never
     * consumes an SMS credit.
     *
     * @param session       the interactive login session (its downstream marker
     *                      decides web-vs-native); may be {@code null} for the REST
     *                      endpoint, which is then treated as a web flow
     * @param phoneNumber   the phone the OTP would be sent to (any form; normalized
     *                      here)
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web
     *                            flow's phone is unknown and not allowlisted
     */
    public void assertOtpAllowed(LoginSession session, String phoneNumber) {
        if (!isEnabled() || isNativeFlow(session)) {
            return;
        }
        if (isKnownNumber(phoneNumber)) {
            return;
        }
        throw notApproved();
    }

    /** REST OTP-send entry point: no login session, always treated as web. */
    public void assertOtpAllowed(String phoneNumber) {
        assertOtpAllowed(null, phoneNumber);
    }

    /**
     * Rejects a new-account signup from an interactive session whose phone is not on
     * the web allowlist. No-op when the gate is disabled or the session carries the
     * exact native marker.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web
     *                            signup's phone is not allowlisted
     */
    public void assertAllowedForNewUser(LoginSession session) {
        assertAllowedForNewUser(session, session.getPhoneNumber());
    }

    /**
     * REST signup entry point ({@code /signup/complete}): no login session, always
     * treated as web, so a new account is created only for an allowlisted phone.
     * No-op when the gate is disabled.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when the phone
     *                            is not allowlisted
     */
    public void assertAllowedForNewUser(String phoneNumber) {
        assertAllowedForNewUser(null, phoneNumber);
    }

    private void assertAllowedForNewUser(LoginSession session, String phoneNumber) {
        if (!isEnabled() || isNativeFlow(session)) {
            return;
        }
        if (!isPhoneAllowlisted(phoneNumber)) {
            throw notApproved();
        }
    }

    /** Whether the beta gate is switched on. */
    public boolean isEnabled() {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        return registration != null && registration.isWebAllowlistEnabled();
    }

    /**
     * Only a session whose downstream marker is exactly the configured native marker
     * is exempt. No session, no marker, an empty marker, a differently cased or
     * otherwise unrecognised value, and the web marker all count as web.
     */
    private boolean isNativeFlow(LoginSession session) {
        if (session == null) {
            return false;
        }
        String nativeMarker = properties.getRegistration().getNativeClientMarker();
        return nativeMarker != null && nativeMarker.equals(session.getDownstreamClient());
    }

    /**
     * A phone is known when it already resolves to an account or is allowlisted.
     * Cheapest check first: the in-memory allowlist, then the directory digest (DB),
     * then the homeserver phone binding (remote) only as a pepper-drift fallback.
     */
    private boolean isKnownNumber(String phoneNumber) {
        String normalized = phoneNumberNormalizer.toE164(phoneNumber);
        if (isPhoneAllowlisted(normalized)) {
            return true;
        }
        String digest = phoneNumberHasher.digest(normalized);
        if (directoryService.findByDigest(digest).isPresent()) {
            return true;
        }
        return matrixAdminClient.findUserIdByPhone(normalized).isPresent();
    }

    private boolean isPhoneAllowlisted(String phoneNumber) {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        List<String> allowlist = registration.getWebAllowlist();
        if (allowlist == null || allowlist.isEmpty()) {
            return false;
        }
        String normalizedPhone = phoneNumberNormalizer.toE164(phoneNumber);
        Set<String> normalizedAllowlist = new HashSet<>();
        for (String entry : allowlist) {
            if (entry == null || entry.isBlank()) {
                continue;
            }
            // Skip unparseable entries rather than failing the whole check on one bad
            // config line; a malformed allowlist entry simply matches nobody.
            try {
                normalizedAllowlist.add(phoneNumberNormalizer.toE164(entry));
            } catch (RuntimeException ex) {
                // Ignore: an invalid allowlist entry contributes no match.
            }
        }
        return normalizedAllowlist.contains(normalizedPhone);
    }

    private static LoginFlowException notApproved() {
        return new LoginFlowException(HttpStatus.FORBIDDEN, "registration_not_approved",
                "This number is not approved for web sign-up yet. Gua Web is available to Gua beta testers only.");
    }
}
