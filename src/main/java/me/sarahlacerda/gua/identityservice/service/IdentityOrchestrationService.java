package me.sarahlacerda.gua.identityservice.service;

import java.util.List;
import java.util.Optional;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
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
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final UserSecurityService userSecurityService;
    private final TrustedDeviceService trustedDeviceService;
    private final DeviceNotificationService deviceNotificationService;

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        otpService.sendOtp(e164PhoneNumber, requesterIp, language);
    }

    public MatrixSession verifyOtpAndSignIn(
        String e164PhoneNumber,
        String code,
        String displayName,
        String providedPin,
        DeviceMetadata deviceMetadata
    ) {
        otpService.verifyOtp(e164PhoneNumber, code);

        final String digest = phoneNumberHasher.digest(e164PhoneNumber);

        final Optional<DirectoryEntry> existingEntry = directoryService.findByDigest(digest);

        final boolean isNewUser = existingEntry.isEmpty();

        final String userId = isNewUser
                ? matrixProvisioningService.generateOpaqueUserId()
                : existingEntry.get().getUserId();

        if (!isNewUser && userSecurityService.hasPin(userId)) {
            userSecurityService.validatePinOrThrow(userId, providedPin);
        } else if (StringUtils.hasText(providedPin)) {
            userSecurityService.setInitialPin(userId, providedPin);
        }

        @Nullable
        final String resolvedDisplayName = resolveDisplayName(displayName, existingEntry);

        final MatrixSession session = matrixProvisioningService.ensureSessionForUser(
            userId,
            e164PhoneNumber,
            resolvedDisplayName,
            isNewUser
        );

        directoryService.upsertByDigest(digest, userId, resolvedDisplayName);

        userSecurityService.recordSuccessfulLogin(userId);

        if (deviceMetadata != null && session.deviceId() != null) {
            boolean newDevice = trustedDeviceService.registerDevice(userId, session.deviceId(), deviceMetadata);
            if (newDevice) {
                deviceNotificationService.notifyNewDevice(userId, session.deviceId(), deviceMetadata);
            }
        }

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

        directoryService.upsertByDigest(newDigest, userId, displayName);
    }

    private String resolveDisplayName(String requestedDisplayName, Optional<DirectoryEntry> existingEntry) {
        if (StringUtils.hasText(requestedDisplayName)) {
            return requestedDisplayName;
        }

        return existingEntry.map(DirectoryEntry::getDisplayName).orElse(null);
    }
}
