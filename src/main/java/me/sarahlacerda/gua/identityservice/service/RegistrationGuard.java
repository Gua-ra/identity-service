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

@Component
@RequiredArgsConstructor
public class RegistrationGuard {

    private final LoginFlowProperties properties;
    private final PhoneNumberNormalizer phoneNumberNormalizer;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final MatrixAdminClient matrixAdminClient;

    /** A null session is treated as a web flow. */
    public void assertOtpAllowed(LoginSession session, String phoneNumber) {
        if (!isEnabled() || isNativeFlow(session)) {
            return;
        }
        if (isKnownNumber(phoneNumber)) {
            return;
        }
        throw notApproved();
    }

    public void assertOtpAllowed(String phoneNumber) {
        assertOtpAllowed(null, phoneNumber);
    }

    public void assertAllowedForNewUser(LoginSession session) {
        assertAllowedForNewUser(session, session.getPhoneNumber());
    }

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

    private boolean isNativeFlow(LoginSession session) {
        if (session == null) {
            return false;
        }
        String nativeMarker = properties.getRegistration().getNativeClientMarker();
        return nativeMarker != null && nativeMarker.equals(session.getDownstreamClient());
    }

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
