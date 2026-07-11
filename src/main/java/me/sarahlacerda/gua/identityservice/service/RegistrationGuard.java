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
 * burn SMS credits or self-register open accounts, while leaving the invited
 * mobile apps and every returning user unaffected.
 *
 * <p>
 * It has two enforcement points, both driven by the SAME master switch
 * {@code idp.login.registration.web-allowlist-enabled} and both no-ops when it is
 * off, so the whole gate is a single flag flip away from the fully-open behaviour
 * (nothing here is baked into the normal code path):
 *
 * <ol>
 * <li><b>OTP send</b> ({@link #assertOtpAllowed}) — the earliest point, before any
 * SMS is dispatched. A web flow may only trigger an OTP for a phone that is
 * already a known account or is explicitly allowlisted; an unknown web number is
 * refused with {@code 403 registration_not_approved} and no SMS is sent. This is
 * what actually stops the credit burn, since the OTP is dispatched several steps
 * before an account is ever created.</li>
 * <li><b>New-account creation</b> ({@link #assertAllowedForNewUser}) — defence in
 * depth at the profile step, before the directory write, so a brand-new web
 * signup whose phone is not allowlisted cannot be provisioned even if it somehow
 * obtained an OTP.</li>
 * </ol>
 *
 * <p>
 * A phone is "known" when it already resolves to an account (directory digest, or
 * the homeserver phone binding as a pepper-drift fallback) OR is on the configured
 * allowlist. Because any account registered through the mobile apps lands in the
 * directory, an app-registered number is automatically recognised here and can log
 * in on the web with no extra plumbing — that is the intended "app registers, then
 * the web works too" behaviour.
 *
 * <p>
 * The gate fails closed. A session is treated as a web flow when its forwarded
 * downstream marker equals the configured web marker OR is absent (MAS did not
 * forward the signal); only an explicit non-web marker (e.g. {@code native}) is
 * exempt. Requests with no session at all (the legacy REST OTP endpoint) are always
 * treated as web.
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
     * nor allowlisted. No-op when the gate is disabled or the flow is a non-web
     * (native app) client. Called before the SMS is sent, so a blocked number never
     * consumes an SMS credit.
     *
     * @param session       the interactive login session (its downstream marker
     *                      decides web-vs-native); may be {@code null} for the legacy
     *                      REST endpoint, which is then treated as a web flow
     * @param phoneNumber   the phone the OTP would be sent to (any form; normalized
     *                      here)
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web
     *                            flow's phone is unknown and not allowlisted
     */
    public void assertOtpAllowed(LoginSession session, String phoneNumber) {
        if (!isEnabled()) {
            return;
        }
        // Native app flows are exempt: the apps are distributed to invited testers
        // only, so they may register brand-new numbers. Everything else (web, or an
        // absent marker) is gated.
        if (session != null && !isWebFlow(session)) {
            return;
        }
        if (isKnownNumber(phoneNumber)) {
            return;
        }
        throw notApproved();
    }

    /** Legacy REST OTP-send entry point: no login session, always treated as web. */
    public void assertOtpAllowed(String phoneNumber) {
        assertOtpAllowed(null, phoneNumber);
    }

    /**
     * Rejects a new-account signup whose phone is not on the web allowlist.
     * No-op when the gate is disabled or the signup is from a non-web client.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web
     *                            signup's phone is not allowlisted
     */
    public void assertAllowedForNewUser(LoginSession session) {
        if (!isEnabled()) {
            return;
        }
        if (!isWebFlow(session)) {
            return;
        }
        if (!isPhoneAllowlisted(session.getPhoneNumber())) {
            throw notApproved();
        }
    }

    /** Whether the beta gate is switched on. */
    public boolean isEnabled() {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        return registration != null && registration.isWebAllowlistEnabled();
    }

    /**
     * A session is a web flow (and therefore gated) when its downstream marker is the
     * configured web marker or is absent. Fail closed: an absent marker is web.
     */
    private boolean isWebFlow(LoginSession session) {
        String downstream = session.getDownstreamClient();
        return downstream == null || downstream.equals(properties.getRegistration().getWebClientMarker());
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

    private boolean isPhoneAllowlisted(String sessionPhone) {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        List<String> allowlist = registration.getWebAllowlist();
        if (allowlist == null || allowlist.isEmpty()) {
            return false;
        }
        String normalizedPhone = phoneNumberNormalizer.toE164(sessionPhone);
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
                "New account sign-ups are currently invite-only. This phone number is not on the list yet.");
    }
}
