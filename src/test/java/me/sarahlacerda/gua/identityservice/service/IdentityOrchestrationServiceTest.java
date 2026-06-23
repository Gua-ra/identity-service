package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.domain.VerifyOtpResult;
import me.sarahlacerda.gua.identityservice.exception.InvalidUsernameException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
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
        private MatrixAdminClient matrixAdminClient;
        @Mock
        private SignupTokenService signupTokenService;
        @Mock
        private PinChallengeService pinChallengeService;
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
        @Mock
        private me.sarahlacerda.gua.identityservice.service.routing.ResolverDirectoryClient resolverDirectoryClient;

        private final UsernamePolicy usernamePolicy = new UsernamePolicy();
        private final io.micrometer.core.instrument.MeterRegistry meterRegistry =
                        new io.micrometer.core.instrument.simple.SimpleMeterRegistry();

        private IdentityOrchestrationService service;

        @BeforeEach
        void setUp() {
                service = new IdentityOrchestrationService(
                                otpService,
                                matrixProvisioningService,
                                matrixAdminClient,
                                signupTokenService,
                                pinChallengeService,
                                directoryService,
                                phoneNumberHasher,
                                new PhoneNumberMasker(),
                                userSecurityService,
                                trustedDeviceService,
                                deviceNotificationService,
                                usernamePolicy,
                                resolverDirectoryClient,
                                meterRegistry);
        }

        @Test
        void verifyOtpAndSignInIssuesSignupTokenForNewPhone() {
                String phone = "+12025550123";
                String digest = "digest";
                DeviceMetadata metadata = DeviceMetadata.builder()
                                .deviceName("iPhone")
                                .platform("iOS")
                                .appVersion("1.0.0")
                                .ipAddress("127.0.0.1")
                                .build();

                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.empty());
                when(signupTokenService.issue(phone)).thenReturn("signup-abc");

                VerifyOtpResult result = service.verifyOtpAndSignIn(phone, "123456", null, metadata);

                verify(otpService).verifyOtp(phone, "123456");
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(), eq(true));
                verify(directoryService, never()).upsertByDigest(any(), anyString(), any(), any());
                assertThat(result.isNewUser()).isTrue();
                assertThat(result.signupToken()).isEqualTo("signup-abc");
                assertThat(result.session()).isNull();
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
                MatrixSession session = new MatrixSession("existing-token", existingEntry.getUserId(), "device-9",
                                CLIENT_BASE_URL);

                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.of(existingEntry));
                when(userSecurityService.hasPin(existingEntry.getUserId())).thenReturn(true);
                when(matrixProvisioningService.ensureSessionForUser(existingEntry.getUserId(), phone, "Existing User",
                                true))
                                .thenReturn(session);
                when(trustedDeviceService.registerDevice(existingEntry.getUserId(), "device-9", metadata))
                                .thenReturn(false);

                VerifyOtpResult result = service.verifyOtpAndSignIn(phone, "000000", "111111", metadata);

                verify(signupTokenService, never()).issue(any());
                verify(matrixProvisioningService, never()).generateOpaqueUserId();
                verify(userSecurityService).validatePinOrThrow(existingEntry.getUserId(), "111111");
                verify(userSecurityService, never()).setInitialPin(any(), any());
                verify(directoryService).upsertByDigest(eq(digest), anyString(), eq(existingEntry.getUserId()),
                                eq("Existing User"));
                verify(userSecurityService).recordSuccessfulLogin(existingEntry.getUserId());
                verify(deviceNotificationService, never()).notifyNewDevice(any(), any(), any());
                assertThat(result.isNewUser()).isFalse();
                assertThat(result.session()).isEqualTo(session);
        }

        @Test
        void completeSignupProvisionsMatrixWithChosenUsernameAndDisplayName() {
                String phone = "+12025550123";
                String digest = "new-digest";
                String userId = "@alice:gua.global";
                MatrixSession session = new MatrixSession("token", userId, "device-1", CLIENT_BASE_URL);
                DeviceMetadata metadata = DeviceMetadata.builder()
                                .deviceName("iPhone")
                                .platform("iOS")
                                .appVersion("1.0.0")
                                .ipAddress("127.0.0.1")
                                .build();

                when(signupTokenService.peek("signup-abc")).thenReturn(phone);
                when(signupTokenService.consume("signup-abc")).thenReturn(phone);
                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.empty());
                when(matrixProvisioningService.buildUserId("alice")).thenReturn(userId);
                when(matrixAdminClient.userExists(userId)).thenReturn(false);
                when(matrixProvisioningService.ensureSessionForUser(userId, phone, "Alice L.", true))
                                .thenReturn(session);
                when(trustedDeviceService.registerDevice(userId, "device-1", metadata)).thenReturn(true);

                MatrixSession result = service.completeSignup("signup-abc", "Alice", "Alice L.", "654321", metadata);

                verify(signupTokenService).consume("signup-abc");
                verify(userSecurityService).setInitialPin(userId, "654321");
                verify(directoryService).upsertByDigest(eq(digest), anyString(), eq(userId), eq("Alice L."));
                verify(userSecurityService).recordSuccessfulLogin(userId);
                verify(deviceNotificationService).notifyNewDevice(userId, "device-1", metadata);
                assertThat(result).isEqualTo(session);
        }

        @Test
        void completeSignupRejectsInvalidUsername() {
                assertThatThrownBy(() -> service.completeSignup("token", "ab", "Display", null, null))
                                .isInstanceOf(InvalidUsernameException.class);

                verify(signupTokenService, never()).consume(any());
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(), eq(true));
        }

        @Test
        void completeSignupRejectsReservedUsername() {
                assertThatThrownBy(() -> service.completeSignup("token", "admin", "Display", null, null))
                                .isInstanceOf(InvalidUsernameException.class);

                verify(signupTokenService, never()).consume(any());
        }

        @Test
        void completeSignupRejectsAllNumericUsername() {
                assertThatThrownBy(() -> service.completeSignup("token", "555", "Display", null, null))
                                .isInstanceOf(InvalidUsernameException.class);

                verify(signupTokenService, never()).consume(any());
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(), eq(true));
        }

        @Test
        void completeSignupRejectsTakenUsernameWithoutConsumingToken() {
                when(signupTokenService.peek("token")).thenReturn("+12025550123");
                when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
                when(directoryService.findByDigest("digest")).thenReturn(Optional.empty());
                when(matrixProvisioningService.buildUserId("alice")).thenReturn("@alice:gua.global");
                when(matrixAdminClient.userExists("@alice:gua.global")).thenReturn(true);

                assertThatThrownBy(() -> service.completeSignup("token", "alice", "Alice", null, null))
                                .isInstanceOf(UsernameTakenException.class);

                verify(signupTokenService, never()).consume(any());
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(), eq(true));
        }

        @Test
        void completeSignupRejectsWhenPhoneAlreadyLinkedConcurrently() {
                when(signupTokenService.peek("token")).thenReturn("+12025550123");
                when(phoneNumberHasher.digest("+12025550123")).thenReturn("digest");
                when(directoryService.findByDigest("digest"))
                                .thenReturn(Optional
                                                .of(DirectoryEntry.builder().phoneDigest("digest")
                                                                .userId("@other:gua.global").build()));

                assertThatThrownBy(() -> service.completeSignup("token", "alice", "Alice", null, null))
                                .isInstanceOf(PhoneAlreadyLinkedException.class);

                verify(signupTokenService, never()).consume(any());
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
                MatrixSession session = new MatrixSession("token", existingEntry.getUserId(), "device-1",
                                CLIENT_BASE_URL);

                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.of(existingEntry));
                when(userSecurityService.hasPin(existingEntry.getUserId())).thenReturn(false);
                when(matrixProvisioningService.ensureSessionForUser(existingEntry.getUserId(), phone, "Existing User",
                                true))
                                .thenReturn(session);

                service.verifyOtpAndSignIn(phone, "123456", null, null);

                verify(trustedDeviceService, never()).registerDevice(any(), any(), any());
                verify(deviceNotificationService, never()).notifyNewDevice(any(), any(), any());
        }

        @Test
        void verifyOtpAndSignInIssuesPinChallengeWhenUserHasPinAndNoPinProvided() {
                String phone = "+12025550100";
                String digest = "pin-digest";
                DirectoryEntry existingEntry = DirectoryEntry.builder()
                                .phoneDigest(digest)
                                .userId("@alice:gua.global")
                                .displayName("Alice")
                                .build();

                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.of(existingEntry));
                when(userSecurityService.hasPin(existingEntry.getUserId())).thenReturn(true);
                when(pinChallengeService.issue(existingEntry.getUserId(), phone)).thenReturn("chal-xyz");

                VerifyOtpResult result = service.verifyOtpAndSignIn(phone, "123456", null, null);

                verify(otpService).verifyOtp(phone, "123456");
                verify(userSecurityService, never()).validatePinOrThrow(any(), any());
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(),
                                any(Boolean.class));
                assertThat(result.isPinRequired()).isTrue();
                assertThat(result.pinChallengeToken()).isEqualTo("chal-xyz");
                assertThat(result.session()).isNull();
        }

        @Test
        void verifySignInPinValidatesPinAndIssuesSession() {
                String phone = "+12025550100";
                String digest = "pin-digest";
                DirectoryEntry entry = DirectoryEntry.builder()
                                .phoneDigest(digest)
                                .userId("@alice:gua.global")
                                .displayName("Alice")
                                .build();
                MatrixSession session = new MatrixSession("token-1", entry.getUserId(), "device-x", CLIENT_BASE_URL);
                DeviceMetadata metadata = DeviceMetadata.builder()
                                .deviceName("iPhone")
                                .platform("iOS")
                                .appVersion("1.0.0")
                                .ipAddress("10.0.0.1")
                                .build();

                when(pinChallengeService.peek("chal-xyz"))
                                .thenReturn(new PinChallengeService.Challenge(entry.getUserId(), phone));
                when(phoneNumberHasher.digest(phone)).thenReturn(digest);
                when(directoryService.findByDigest(digest)).thenReturn(Optional.of(entry));
                when(matrixProvisioningService.ensureSessionForUser(entry.getUserId(), phone, "Alice", true))
                                .thenReturn(session);

                MatrixSession result = service.verifySignInPin("chal-xyz", "654321", metadata);

                verify(userSecurityService).validatePinOrThrow(entry.getUserId(), "654321");
                verify(pinChallengeService).consume("chal-xyz");
                verify(directoryService).upsertByDigest(eq(digest), anyString(), eq(entry.getUserId()), eq("Alice"));
                verify(userSecurityService).recordSuccessfulLogin(entry.getUserId());
                assertThat(result).isEqualTo(session);
        }

        @Test
        void verifySignInPinRejectsWhenDirectoryNoLongerLinksPhoneToChallengeUser() {
                DirectoryEntry otherEntry = DirectoryEntry.builder()
                                .phoneDigest("d")
                                .userId("@somebody-else:gua.global")
                                .build();

                when(pinChallengeService.peek("chal-xyz"))
                                .thenReturn(new PinChallengeService.Challenge("@alice:gua.global", "+12025550100"));
                when(phoneNumberHasher.digest("+12025550100")).thenReturn("d");
                when(directoryService.findByDigest("d")).thenReturn(Optional.of(otherEntry));

                assertThatThrownBy(() -> service.verifySignInPin("chal-xyz", "654321", null))
                                .isInstanceOf(PhoneAlreadyLinkedException.class);

                verify(pinChallengeService, never()).consume(any());
                verify(matrixProvisioningService, never()).ensureSessionForUser(any(), any(), any(),
                                any(Boolean.class));
        }
}
