package me.sarahlacerda.gua.identityservice.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

/**
 * Gates the creation of a brand-new account behind a phone-number allowlist,
 * used to keep web signups invite-only during a limited rollout while the mobile
 * apps stay fully open.
 *
 * <p>
 * Scope is deliberately narrow: this runs only on the new-account branch of the
 * interactive login flow (the profile step, before the directory write). Existing
 * users signing in, re-authentication, change-phone, and passkey sign-in/enroll
 * are all structurally outside that branch and are never subject to it.
 *
 * <p>
 * The guard fails closed. A session is treated as a web signup when its forwarded
 * downstream marker equals the configured web marker OR is absent (MAS did not
 * forward the signal): in both cases the allowlist applies. Only an explicit
 * non-web marker (e.g. {@code native}) is exempt. The guard is inert unless
 * {@code idp.login.registration.web-allowlist-enabled} is on.
 */
@Component
@RequiredArgsConstructor
public class RegistrationGuard {

    private final LoginFlowProperties properties;
    private final PhoneNumberNormalizer phoneNumberNormalizer;

    /**
     * Rejects a new-account signup whose phone is not on the web allowlist.
     * No-op when the allowlist is disabled or the signup is from a non-web client.
     *
     * @throws LoginFlowException {@code 403 registration_not_approved} when a web
     *                            signup's phone is not allowlisted
     */
    public void assertAllowedForNewUser(LoginSession session) {
        LoginFlowProperties.Registration registration = properties.getRegistration();
        if (registration == null || !registration.isWebAllowlistEnabled()) {
            return;
        }

        String marker = registration.getWebClientMarker();
        String downstream = session.getDownstreamClient();
        // Fail closed: an absent downstream signal is treated as a web signup.
        boolean isWebSignup = downstream == null || downstream.equals(marker);
        if (!isWebSignup) {
            return;
        }

        if (!isPhoneAllowlisted(session.getPhoneNumber(), registration.getWebAllowlist())) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "registration_not_approved",
                    "New account sign-ups are currently invite-only. This phone number is not on the list yet.");
        }
    }

    private boolean isPhoneAllowlisted(String sessionPhone, List<String> allowlist) {
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
}
