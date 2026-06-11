package me.sarahlacerda.gua.identityservice.service;

import java.util.List;
import java.util.Optional;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.domain.VerifyOtpResult;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.service.security.DeviceNotificationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@Service
@RequiredArgsConstructor
public class IdentityOrchestrationService {

    private final OtpService otpService;
    private final MatrixProvisioningService matrixProvisioningService;
    private final MatrixAdminClient matrixAdminClient;
    private final SignupTokenService signupTokenService;
    private final PinChallengeService pinChallengeService;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final UserSecurityService userSecurityService;
    private final TrustedDeviceService trustedDeviceService;
    private final DeviceNotificationService deviceNotificationService;
    private final UsernamePolicy usernamePolicy;

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        otpService.sendOtp(e164PhoneNumber, requesterIp, language);
    }

    public VerifyOtpResult verifyOtpAndSignIn(
            String e164PhoneNumber,
            String code,
            String providedPin,
            DeviceMetadata deviceMetadata) {
        otpService.verifyOtp(e164PhoneNumber, code);

        final String digest = phoneNumberHasher.digest(e164PhoneNumber);
        final Optional<DirectoryEntry> existingEntry = directoryService.findByDigest(digest);

        if (existingEntry.isEmpty()) {
            // New user: defer Matrix provisioning until they choose a username + display
            // name.
            String signupToken = signupTokenService.issue(e164PhoneNumber);
            return VerifyOtpResult.newUser(signupToken);
        }

        final DirectoryEntry entry = existingEntry.get();
        final String userId = entry.getUserId();

        if (userSecurityService.hasPin(userId)) {
            if (!StringUtils.hasText(providedPin)) {
                // Two-step verification: issue a short-lived challenge token that the
                // client redeems at /signin/verify-pin with the user's PIN. The OTP has
                // been consumed and won't be re-checked; this token is the sole proof
                // that the phone was just verified.
                String challengeToken = pinChallengeService.issue(userId, e164PhoneNumber);
                return VerifyOtpResult.pinRequired(challengeToken);
            }
            userSecurityService.validatePinOrThrow(userId, providedPin);
        }

        return completeSignIn(entry, e164PhoneNumber, deviceMetadata);
    }

    /**
     * Second leg of the two-step phone sign-in: consumes the pin-challenge token
     * issued by {@link #verifyOtpAndSignIn} and validates the user's PIN before
     * minting a Matrix session.
     */
    public MatrixSession verifySignInPin(String pinChallengeToken, String pin, DeviceMetadata deviceMetadata) {
        // Peek first so a wrong-PIN attempt doesn't burn the user's verified-OTP proof;
        // the
        // UserSecurityService failure-count + lockout policy prevents brute force on a
        // live token.
        PinChallengeService.Challenge challenge = pinChallengeService.peek(pinChallengeToken);
        userSecurityService.validatePinOrThrow(challenge.userId(), pin);

        final String digest = phoneNumberHasher.digest(challenge.phone());
        final DirectoryEntry entry = directoryService.findByDigest(digest)
                .orElseThrow(() -> new PhoneAlreadyLinkedException("Phone number no longer linked to this account"));

        if (!entry.getUserId().equals(challenge.userId())) {
            throw new PhoneAlreadyLinkedException("Phone number no longer linked to this account");
        }

        // Everything checks out: consume the token now so it can't be reused.
        pinChallengeService.consume(pinChallengeToken);

        VerifyOtpResult result = completeSignIn(entry, challenge.phone(), deviceMetadata);
        return result.session();
    }

    private VerifyOtpResult completeSignIn(DirectoryEntry entry, String e164PhoneNumber,
            DeviceMetadata deviceMetadata) {
        final String userId = entry.getUserId();
        @Nullable
        final String resolvedDisplayName = entry.getDisplayName();

        // Always re-link the phone on sign-in. After a previous account deactivation
        // the
        // homeserver drops all linked threepids, so signing back in with the same phone
        // must
        // restore the binding — otherwise downstream flows that look up the user's
        // phone (e.g.
        // /account/reauth/start) will fail with "no phone number linked".
        final MatrixSession session = matrixProvisioningService.ensureSessionForUser(
                userId,
                e164PhoneNumber,
                resolvedDisplayName,
                true);

        final String digest = phoneNumberHasher.digest(e164PhoneNumber);
        directoryService.upsertByDigest(digest, userId, resolvedDisplayName);
        userSecurityService.recordSuccessfulLogin(userId);
        registerDeviceIfPresent(userId, session, deviceMetadata);

        return VerifyOtpResult.existingUser(session);
    }

    public MatrixSession completeSignup(
            String signupToken,
            String username,
            String displayName,
            String providedPin,
            DeviceMetadata deviceMetadata) {
        // Validate every recoverable input BEFORE consuming the single-use signup token
        // so the
        // client can correct mistakes (username taken, invalid format, etc.) and retry
        // with the
        // same token instead of having to redo the OTP flow.
        final String localpart = validateUsername(username);
        final String userId = matrixProvisioningService.buildUserId(localpart);

        final String phone = signupTokenService.peek(signupToken);
        final String digest = phoneNumberHasher.digest(phone);

        if (directoryService.findByDigest(digest).isPresent()) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        if (matrixAdminClient.userExists(userId)) {
            throw new UsernameTakenException("Username already taken");
        }

        // All pre-flight checks passed; from here we commit the signup. Consume the
        // token first so
        // a duplicate request can't race past the userExists check.
        signupTokenService.consume(signupToken);

        final String resolvedDisplayName = StringUtils.hasText(displayName) ? displayName.trim() : localpart;

        if (StringUtils.hasText(providedPin)) {
            userSecurityService.setInitialPin(userId, providedPin);
        }

        final MatrixSession session = matrixProvisioningService.ensureSessionForUser(
                userId,
                phone,
                resolvedDisplayName,
                true);

        try {
            directoryService.upsertByDigest(digest, userId, resolvedDisplayName);
        } catch (DataIntegrityViolationException ex) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        userSecurityService.recordSuccessfulLogin(userId);
        registerDeviceIfPresent(userId, session, deviceMetadata);

        return session;
    }

    public void changePhoneNumber(String userId, String newPhone, String code, String pin) {
        otpService.verifyOtp(newPhone, code);
        userSecurityService.validatePinOrThrow(userId, pin);

        final String newDigest = phoneNumberHasher.digest(newPhone);

        directoryService.findByDigest(newDigest)
                .filter(entry -> !entry.getUserId().equals(userId))
                .ifPresent(entry -> {
                    throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
                });

        matrixProvisioningService.ensureExclusivePhoneBinding(userId, newPhone);

        List<DirectoryEntry> currentEntries = directoryService.findByUserId(userId);

        final String displayName = currentEntries.stream()
                .map(DirectoryEntry::getDisplayName)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);

        currentEntries.stream()
                .map(DirectoryEntry::getPhoneDigest)
                .filter(digest -> !digest.equals(newDigest))
                .forEach(directoryService::deleteByDigest);

        try {
            directoryService.upsertByDigest(newDigest, userId, displayName);
        } catch (DataIntegrityViolationException ex) {
            // Concurrent request already bound this digest to a different account; surface
            // a clean conflict.
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }
    }

    private void registerDeviceIfPresent(String userId, MatrixSession session, DeviceMetadata deviceMetadata) {
        if (deviceMetadata != null && session.deviceId() != null) {
            boolean newDevice = trustedDeviceService.registerDevice(userId, session.deviceId(), deviceMetadata);
            if (newDevice) {
                deviceNotificationService.notifyNewDevice(userId, session.deviceId(), deviceMetadata);
            }
        }
    }

    private String validateUsername(String rawUsername) {
        return usernamePolicy.normalizeAndValidate(rawUsername);
    }

    /**
     * Lightweight availability check used by the signup UI for real-time
     * validation.
     * Runs the same format + reserved-name checks as {@link #completeSignup}
     * (throwing
     * {@link InvalidUsernameException} on bad input) and returns {@code true} only
     * when
     * no Matrix account with that localpart already exists. Does not mutate state.
     */
    public boolean isUsernameAvailable(String rawUsername) {
        String localpart = validateUsername(rawUsername);
        String userId = matrixProvisioningService.buildUserId(localpart);
        return !matrixAdminClient.userExists(userId);
    }
}
