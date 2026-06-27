package me.sarahlacerda.gua.identityservice.service;

import java.util.List;
import java.util.Optional;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.domain.VerifyOtpResult;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.service.routing.ResolverDirectoryClient;
import me.sarahlacerda.gua.identityservice.service.security.DeviceNotificationService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthTokenService;
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
    private final PhoneNumberMasker phoneNumberMasker;
    private final UserSecurityService userSecurityService;
    private final ReauthTokenService reauthTokenService;
    private final TrustedDeviceService trustedDeviceService;
    private final DeviceNotificationService deviceNotificationService;
    private final UsernamePolicy usernamePolicy;
    private final ResolverDirectoryClient resolverDirectoryClient;
    private final MeterRegistry metrics;

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
        directoryService.upsertByDigest(digest, phoneNumberMasker.mask(e164PhoneNumber), userId, resolvedDisplayName);
        // Keep the shared resolver directory in sync (covers accounts created before this integration).
        resolverDirectoryClient.registerPhone(e164PhoneNumber);
        // gua_identity_login_total{result} — successful sign-ins of existing accounts.
        metrics.counter("gua.identity.login", "result", "success").increment();
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
            directoryService.upsertByDigest(digest, phoneNumberMasker.mask(phone), userId, resolvedDisplayName);
        } catch (DataIntegrityViolationException ex) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        // Publish to the gua-resolver shared directory so the federation front door can route this phone
        // to us (best-effort; the local directory above is authoritative for our own users).
        resolverDirectoryClient.registerPhone(phone);

        // gua_identity_signup_total{result,country} — completed new-account
        // registrations, tagged with the ISO region of the (E.164) phone for the
        // Grafana registrations-by-country panel. country is low-cardinality (~200 ISO
        // codes); never tag with the phone itself or any per-user value.
        metrics.counter("gua.identity.signup", "result", "success", "country", regionOf(phone)).increment();
        userSecurityService.recordSuccessfulLogin(userId);
        registerDeviceIfPresent(userId, session, deviceMetadata);

        return session;
    }

    /**
     * Step two of the change-phone flow: validates the single-use reauth token from the PIN
     * step-up WITHOUT consuming it, then dispatches the OTP SMS to the new number. Gating the
     * SMS on a live token guarantees no message fires before a successful PIN step-up.
     */
    public void requestPhoneChangeOtp(String userId, String newPhone, String reauthToken, String ip,
            String language) {
        reauthTokenService.validate(reauthToken, userId);
        // Defense-in-depth: even with a valid reauth token, refuse to send the new-number OTP
        // while the post-PIN-write 2FA cooldown is active, so a SIM-swapper who just set a PIN
        // can't get instant trust. The client also pre-checks this via /security/pin/status.
        long cooldownRemaining = userSecurityService.changePhoneCooldownRemainingSeconds(userId);
        if (cooldownRemaining > 0) {
            throw new TwoFactorCooldownException(
                    "Change-phone two-factor cooldown active", cooldownRemaining);
        }
        sendOtp(newPhone, ip, language);
    }

    public void changePhoneNumber(String userId, String newPhone, String code, String reauthToken) {
        otpService.verifyOtp(newPhone, code);
        reauthTokenService.consume(reauthToken, userId);

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
            directoryService.upsertByDigest(newDigest, phoneNumberMasker.mask(newPhone), userId, displayName);
        } catch (DataIntegrityViolationException ex) {
            // Concurrent request already bound this digest to a different account; surface
            // a clean conflict.
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }
    }

    /**
     * Resolves the ISO 3166-1 alpha-2 region of an E.164 phone for the
     * registrations-by-country metric. Returns {@code "unknown"} when the number
     * can't be parsed or has no region, keeping the {@code country} tag
     * low-cardinality (~200 ISO codes) and free of any per-user value.
     */
    private static String regionOf(String e164PhoneNumber) {
        if (!StringUtils.hasText(e164PhoneNumber)) {
            return "unknown";
        }
        try {
            PhoneNumberUtil util = PhoneNumberUtil.getInstance();
            String region = util.getRegionCodeForNumber(util.parse(e164PhoneNumber, null));
            return region != null ? region : "unknown";
        } catch (NumberParseException ex) {
            return "unknown";
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
