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
 * Web registration gate. Keeps an internet-exposed deployment from being used to burn SMS credits or
 * self-register accounts, while leaving the mobile apps and every returning user unaffected. Driven
 * by {@code idp.login.registration.web-allowlist-enabled}; a no-op when it is off.
 *
 * <ol>
 * <li><b>OTP send</b> ({@link #assertOtpAllowed}): a web flow may trigger an OTP only for a phone
 * that is a known account or is allowlisted; otherwise {@code 403 registration_not_approved}, before
 * any SMS is sent.</li>
 * <li><b>New-account creation</b> ({@link #assertAllowedForNewUser}): before the account is
 * provisioned, on both signup paths ({@code /login/profile} and REST {@code /signup/complete}).</li>
 * </ol>
 *
 * <p>Web versus native comes from the {@code gua_downstream} marker MAS appends to the authorize
 * request. The marker is client-editable, so the exemption is a convenience, not a security
 * boundary, and the gate fails closed: only the exact native marker is exempt. Requests with no login
 * session are always treated as web.
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
     * Rejects an OTP dispatch for a web flow whose phone is neither a known account nor allowlisted.
     * No-op when the gate is disabled or the session carries the exact native marker.
     *
     * @param session     the login session; {@code null} for the REST endpoint, which is treated as web
     * @param phoneNumber the phone the OTP would be sent to (any form; normalized here)
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web flow's phone is
     *                            unknown and not allowlisted
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
     * Rejects a new-account signup from an interactive session whose phone is not on the web allowlist.
     * No-op when the gate is disabled or the session carries the exact native marker.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web signup's phone is
     *                            not allowlisted
     */
    public void assertAllowedForNewUser(LoginSession session) {
        assertAllowedForNewUser(session, session.getPhoneNumber());
    }

    /**
     * REST signup entry point ({@code /signup/complete}): no login session, always treated as web.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when the phone is not allowlisted
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

    public boolean isEnabled() {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        return registration != null && registration.isWebAllowlistEnabled();
    }

    /** Only a session whose marker is exactly the configured native marker is exempt. Everything else counts as web. */
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
                // An invalid allowlist entry matches nobody.
            }
        }
        return normalizedAllowlist.contains(normalizedPhone);
    }

    private static LoginFlowException notApproved() {
        return new LoginFlowException(HttpStatus.FORBIDDEN, "registration_not_approved",
                "This number is not approved for web sign-up yet. Gua Web is available to Gua beta testers only.");
    }
}
