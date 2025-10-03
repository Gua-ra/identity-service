package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.service.security.DeviceNotificationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

@ExtendWith(MockitoExtension.class)
class IdentityOrchestrationServiceTest {

    private static final String CLIENT_BASE_URL = "https://matrix";

    @Mock
    private OtpService otpService;
    @Mock
    private MatrixProvisioningService matrixProvisioningService;
    @Mock
    private DirectoryService directoryService;
    @Mock
    private PhoneNumberHasher phoneNumberHasher;
    @Mock
    private UserSecurityService userSecurityService;
    @Mock
    private TrustedDeviceService trustedDeviceService;
    @Mock
    private DeviceNotificationService deviceNotificationService;

    private IdentityOrchestrationService service;

    @BeforeEach
    void setUp() {
        service = new IdentityOrchestrationService(
            otpService,
            matrixProvisioningService,
            directoryService,
            phoneNumberHasher,
            userSecurityService,
            trustedDeviceService,
            deviceNotificationService
        );
    }

    @Test
    void verifyOtpAndSignInCreatesNewUserAndNotifiesOnNewDevice() {
        String phone = "+12025550123";
        String digest = "digest";
        String generatedUserId = "@opaque:gua.global";
        DeviceMetadata metadata = DeviceMetadata.builder()
            .deviceName("iPhone")
            .platform("iOS")
            .appVersion("1.0.0")
            .ipAddress("127.0.0.1")
            .build();
        MatrixSession session = new MatrixSession("token", generatedUserId, "device-1", CLIENT_BASE_URL);

        when(phoneNumberHasher.digest(phone)).thenReturn(digest);
        when(directoryService.findByDigest(digest)).thenReturn(Optional.empty());
        when(matrixProvisioningService.generateOpaqueUserId()).thenReturn(generatedUserId);
        when(matrixProvisioningService.ensureSessionForUser(generatedUserId, phone, "Alice", true)).thenReturn(session);
        when(trustedDeviceService.registerDevice(generatedUserId, "device-1", metadata)).thenReturn(true);

        MatrixSession result = service.verifyOtpAndSignIn(phone, "123456", "Alice", "654321", metadata);

        verify(otpService).verifyOtp(phone, "123456");
        verify(userSecurityService, never()).hasPin(any());
        verify(userSecurityService).setInitialPin(generatedUserId, "654321");
        verify(matrixProvisioningService).generateOpaqueUserId();
        verify(matrixProvisioningService).ensureSessionForUser(generatedUserId, phone, "Alice", true);
        verify(directoryService).upsertByDigest(digest, generatedUserId, "Alice");
        verify(userSecurityService).recordSuccessfulLogin(generatedUserId);
        verify(deviceNotificationService).notifyNewDevice(generatedUserId, "device-1", metadata);
        assertThat(result).isEqualTo(session);
    }

    @Test
    void verifyOtpAndSignInValidatesPinForExistingUser() {
        String phone = "+12025550199";
        String digest = "existing-digest";
        DirectoryEntry existingEntry = DirectoryEntry.builder()
            .phoneDigest(digest)
            .userId("@existing:gua.global")
            .displayName("Existing User")
            .build();
        DeviceMetadata metadata = DeviceMetadata.builder()
            .deviceName("Pixel")
            .platform("Android")
            .appVersion("2.1.0")
            .ipAddress("10.0.0.5")
            .build();
        MatrixSession session = new MatrixSession("existing-token", existingEntry.getUserId(), "device-9", CLIENT_BASE_URL);

        when(phoneNumberHasher.digest(phone)).thenReturn(digest);
        when(directoryService.findByDigest(digest)).thenReturn(Optional.of(existingEntry));
        when(userSecurityService.hasPin(existingEntry.getUserId())).thenReturn(true);
        when(matrixProvisioningService.ensureSessionForUser(existingEntry.getUserId(), phone, "Existing User", false))
            .thenReturn(session);
        when(trustedDeviceService.registerDevice(existingEntry.getUserId(), "device-9", metadata)).thenReturn(false);

        MatrixSession result = service.verifyOtpAndSignIn(phone, "000000", "", "111111", metadata);

        verify(matrixProvisioningService, never()).generateOpaqueUserId();
        verify(userSecurityService).validatePinOrThrow(existingEntry.getUserId(), "111111");
        verify(userSecurityService, never()).setInitialPin(any(), any());
        verify(directoryService).upsertByDigest(digest, existingEntry.getUserId(), "Existing User");
        verify(userSecurityService).recordSuccessfulLogin(existingEntry.getUserId());
        verify(deviceNotificationService, never()).notifyNewDevice(any(), any(), any());
        assertThat(result).isEqualTo(session);
    }

    @Test
    void changePhoneNumberRebindsDirectoryEntries() {
        String userId = "@user:gua.global";
        String newPhone = "+13035550123";
        String newDigest = "new-digest";
        DirectoryEntry entryOne = DirectoryEntry.builder()
            .phoneDigest("old-1")
            .userId(userId)
            .displayName("Display Name")
            .build();
        DirectoryEntry entryTwo = DirectoryEntry.builder()
            .phoneDigest("old-2")
            .userId(userId)
            .displayName(null)
            .build();

        when(phoneNumberHasher.digest(newPhone)).thenReturn(newDigest);
        when(directoryService.findByDigest(newDigest)).thenReturn(Optional.empty());
        when(directoryService.findByUserId(userId)).thenReturn(List.of(entryOne, entryTwo));

        service.changePhoneNumber(userId, newPhone, "999999", "123456");

        verify(otpService).verifyOtp(newPhone, "999999");
        verify(userSecurityService).validatePinOrThrow(userId, "123456");
        verify(matrixProvisioningService).ensureExclusivePhoneBinding(userId, newPhone);
        verify(directoryService).deleteByDigest("old-1");
        verify(directoryService).deleteByDigest("old-2");
        verify(directoryService).upsertByDigest(newDigest, userId, "Display Name");
    }

    @Test
    void changePhoneNumberRejectsWhenDigestOwnedByAnotherUser() {
        String userId = "@user:gua.global";
        String newPhone = "+13035550123";
        String newDigest = "taken-digest";
        DirectoryEntry other = DirectoryEntry.builder()
            .phoneDigest(newDigest)
            .userId("@other:gua.global")
            .build();

        when(phoneNumberHasher.digest(newPhone)).thenReturn(newDigest);
        when(directoryService.findByDigest(newDigest)).thenReturn(Optional.of(other));

        assertThatThrownBy(() -> service.changePhoneNumber(userId, newPhone, "888888", "123456"))
            .isInstanceOf(PhoneAlreadyLinkedException.class);

        verify(matrixProvisioningService, never()).ensureExclusivePhoneBinding(any(), any());
        verify(directoryService, never()).findByUserId(any());
    }

    @Test
    void verifyOtpAndSignInSkipsDeviceRegistrationWhenMetadataMissing() {
        String phone = "+14045550123";
        String digest = "digest";
        DirectoryEntry existingEntry = DirectoryEntry.builder()
            .phoneDigest(digest)
            .userId("@existing:gua.global")
            .displayName("Existing User")
            .build();
        MatrixSession session = new MatrixSession("token", existingEntry.getUserId(), "device-1", CLIENT_BASE_URL);

        when(phoneNumberHasher.digest(phone)).thenReturn(digest);
        when(directoryService.findByDigest(digest)).thenReturn(Optional.of(existingEntry));
        when(userSecurityService.hasPin(existingEntry.getUserId())).thenReturn(false);
        when(matrixProvisioningService.ensureSessionForUser(existingEntry.getUserId(), phone, "Existing User", false)).thenReturn(session);

        service.verifyOtpAndSignIn(phone, "123456", "Existing User", null, null);

        verify(trustedDeviceService, never()).registerDevice(any(), any(), any());
        verify(deviceNotificationService, never()).notifyNewDevice(any(), any(), any());
    }

    @Test
    void changePhoneNumberAllowsWhenDigestBelongsToSameUser() {
        String userId = "@user:gua.global";
        String newPhone = "+15055550123";
        String newDigest = "existing-digest";
        DirectoryEntry sameUserEntry = DirectoryEntry.builder()
            .phoneDigest(newDigest)
            .userId(userId)
            .displayName("Display").build();
        DirectoryEntry otherEntry = DirectoryEntry.builder()
            .phoneDigest("other")
            .userId(userId)
            .displayName("Display").build();

        when(phoneNumberHasher.digest(newPhone)).thenReturn(newDigest);
        when(directoryService.findByDigest(newDigest)).thenReturn(Optional.of(sameUserEntry));
        when(directoryService.findByUserId(userId)).thenReturn(List.of(sameUserEntry, otherEntry));

        service.changePhoneNumber(userId, newPhone, "111111", "222222");

        verify(matrixProvisioningService).ensureExclusivePhoneBinding(userId, newPhone);
        verify(directoryService).deleteByDigest("other");
        verify(directoryService).upsertByDigest(newDigest, userId, "Display");
    }
}
