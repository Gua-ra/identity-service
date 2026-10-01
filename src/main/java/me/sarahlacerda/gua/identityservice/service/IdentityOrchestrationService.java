package me.sarahlacerda.gua.identityservice.service;

import java.util.Optional;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.domain.VerifyOtpResult;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactorPolicy;
import me.sarahlacerda.gua.identityservice.service.security.DeviceNotificationService;
import me.sarahlacerda.gua.identityservice.service.security.PinPolicy;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@Service
@RequiredArgsConstructor
public class IdentityOrchestrationService {

    private static final Logger log = LoggerFactory.getLogger(IdentityOrchestrationService.class);

    private final OtpService otpService;
    private final MatrixProvisioningService matrixProvisioningService;
    private final MatrixAdminClient matrixAdminClient;
    private final SignupTokenService signupTokenService;
    private final PinChallengeService pinChallengeService;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;
    private final UserSecurityService userSecurityService;
    private final AuthFactorPolicy authFactorPolicy;
    private final TrustedDeviceService trustedDeviceService;
    private final DeviceNotificationService deviceNotificationService;
    private final UsernamePolicy usernamePolicy;
    private final MeterRegistry metrics;
    private final RegistrationGuard registrationGuard;
    private final AccountGenesisService accountGenesisService;
    private final PinPolicy pinPolicy;

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
            String signupToken = signupTokenService.issue(e164PhoneNumber);
            return VerifyOtpResult.newUser(signupToken);
        }

        final DirectoryEntry entry = existingEntry.get();
        final String userId = entry.getUserId();

        // This path cannot run a passkey ceremony or set a first factor, so such accounts are sent to the
        // interactive sign-in.
        AuthFactorPolicy.LoginPolicy loginPolicy = authFactorPolicy.loginPolicy(userId);
        if (loginPolicy.passkeyRequired()) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_required",
                    "This account signs in with a passkey. Update Gua to sign in.");
        }
        if (loginPolicy.factorSetupRequired()) {
            throw new LoginFlowException(HttpStatus.FORBIDDEN, "factor_setup_required",
                    "This account needs a PIN or passkey. Update Gua to sign in.");
        }
        if (loginPolicy.pinStepRequired()) {
            if (!StringUtils.hasText(providedPin)) {
                // The OTP has been consumed. This token is the sole proof that the phone was just verified.
                String challengeToken = pinChallengeService.issue(userId, e164PhoneNumber);
                return VerifyOtpResult.pinRequired(challengeToken);
            }
            userSecurityService.validatePinOrThrow(userId, providedPin);
        }

        return completeSignIn(entry, e164PhoneNumber, deviceMetadata);
    }

    public MatrixSession verifySignInPin(String pinChallengeToken, String pin, DeviceMetadata deviceMetadata) {
        // Peek first so a wrong PIN does not burn the verified-OTP proof.
        PinChallengeService.Challenge challenge = pinChallengeService.peek(pinChallengeToken);
        userSecurityService.validatePinOrThrow(challenge.userId(), pin);

        final String digest = phoneNumberHasher.digest(challenge.phone());
        final DirectoryEntry entry = directoryService.findByDigest(digest)
                .orElseThrow(() -> new PhoneAlreadyLinkedException("Phone number no longer linked to this account"));

        if (!entry.getUserId().equals(challenge.userId())) {
            throw new PhoneAlreadyLinkedException("Phone number no longer linked to this account");
        }

        pinChallengeService.consume(pinChallengeToken);

        VerifyOtpResult result = completeSignIn(entry, challenge.phone(), deviceMetadata);
        return result.session();
    }

    private VerifyOtpResult completeSignIn(DirectoryEntry entry, String e164PhoneNumber,
            DeviceMetadata deviceMetadata) {
        final String userId = entry.getUserId();
        @Nullable
        final String resolvedDisplayName = entry.getDisplayName();

        // Deactivation drops the homeserver's linked threepids, so every sign-in re-links the phone.
        final MatrixSession session = matrixProvisioningService.ensureSessionForUser(
                userId,
                e164PhoneNumber,
                resolvedDisplayName,
                true);

        final String digest = phoneNumberHasher.digest(e164PhoneNumber);
        directoryService.upsertByDigest(digest, phoneNumberMasker.mask(e164PhoneNumber), userId, resolvedDisplayName);
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
        // Validate every recoverable input before consuming the single-use signup token, so the client can
        // retry with it.
        final String localpart = validateUsername(username);
        final String userId = matrixProvisioningService.buildUserId(localpart);

        final String phone = signupTokenService.peek(signupToken);
        registrationGuard.assertAllowedForNewUser(phone);
        final String digest = phoneNumberHasher.digest(phone);

        if (directoryService.findByDigest(digest).isPresent()) {
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        if (matrixAdminClient.userExists(userId)) {
            throw new UsernameTakenException("Username already taken");
        }

        if (!StringUtils.hasText(providedPin)) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "pin_required",
                    "Choose a PIN to protect your account.");
        }
        pinPolicy.validate(providedPin);

        // Consume the token first so a duplicate request cannot race past the userExists check.
        signupTokenService.consume(signupToken);

        final String resolvedDisplayName = StringUtils.hasText(displayName) ? displayName.trim() : localpart;

        userSecurityService.setInitialPin(userId, providedPin);

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

        // No login session exists to hold an attach challenge, so this path always mints a bootstrap id.
        // A failure is logged and left to the backfill, because the signup has already committed.
        if (accountGenesisService.isEnabled()) {
            try {
                accountGenesisService.bootstrap(userId);
            } catch (RuntimeException ex) {
                log.warn("Could not root a new account in a genesis row: {}", ex.getMessage());
            }
        }

        // Never tag with the phone or any per-user value.
        metrics.counter("gua.identity.signup", "result", "success", "country", regionOf(phone)).increment();
        userSecurityService.recordSuccessfulLogin(userId);
        registerDeviceIfPresent(userId, session, deviceMetadata);

        return session;
    }

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

    public boolean isUsernameAvailable(String rawUsername) {
        String localpart = validateUsername(rawUsername);
        String userId = matrixProvisioningService.buildUserId(localpart);
        return !matrixAdminClient.userExists(userId);
    }
}
