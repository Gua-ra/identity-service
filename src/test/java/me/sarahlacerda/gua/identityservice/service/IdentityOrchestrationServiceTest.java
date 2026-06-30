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
        private me.sarahlacerda.gua.identityservice.service.security.ReauthTokenService reauthTokenService;
        @Mock
        private TrustedDeviceService trustedDeviceService;
        @Mock
        private DeviceNotificationService deviceNotificationService;
        @Mock
        private me.sarahlacerda.gua.identityservice.service.routing.ResolverDirectoryClient resolverDirectoryClient;
        @Mock
        private me.sarahlacerda.gua.identityservice.service.security.ChangeNumberSecurityNotifier changeNumberSecurityNotifier;
        @Mock
        private me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger securityAuditLogger;

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
                                reauthTokenService,
                                trustedDeviceService,
                                deviceNotificationService,
                                usernamePolicy,
                                resolverDirectoryClient,
                                changeNumberSecurityNotifier,
                                securityAuditLogger,
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
        void changePhoneNumberRebindsDirectoryEntries() {
                String userId = "@user:gua.global";
                String newPhone = "+13035550123";
                String newDigest = "new-digest";
                DirectoryEntry entryOne = DirectoryEntry.builder()
                                .phoneDigest("old-1")
                                .phoneMasked("••••1111")
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

                service.changePhoneNumber(userId, newPhone, "999999", "reauth-tok");

                verify(otpService).verifyOtp(newPhone, "999999");
                verify(reauthTokenService).consume("reauth-tok", userId);
                verify(matrixProvisioningService).ensureExclusivePhoneBinding(userId, newPhone);
                verify(directoryService).deleteByDigest("old-1");
                verify(directoryService).deleteByDigest("old-2");
                verify(directoryService).upsertByDigest(eq(newDigest), anyString(), eq(userId), eq("Display Name"));
                // Post-change cooldown is opened on the successful rebind, alongside the audit.
                verify(userSecurityService).markPhoneChanged(userId);
                // Completed audit carries only masked phones — the masked old number comes from the
                // unbound directory row, the masked new number from the masker (never plaintext E.164).
                verify(securityAuditLogger).phoneChangeCompleted(userId, "••••1111", "••••0123");
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

                assertThatThrownBy(() -> service.changePhoneNumber(userId, newPhone, "888888", "reauth-tok"))
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

                service.changePhoneNumber(userId, newPhone, "111111", "reauth-tok");

                verify(reauthTokenService).consume("reauth-tok", userId);
                verify(matrixProvisioningService).ensureExclusivePhoneBinding(userId, newPhone);
                verify(directoryService).deleteByDigest("other");
                verify(directoryService).upsertByDigest(eq(newDigest), anyString(), eq(userId), eq("Display"));
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

        @Test
        void requestPhoneChangeOtpSendsWhenNoCooldown() {
                when(userSecurityService.changePhoneCooldownRemainingSeconds("@alice:gua.global")).thenReturn(0L);

                service.requestPhoneChangeOtp("@alice:gua.global", "+12025550199", "reauth-tok", "1.2.3.4", "en");

                verify(reauthTokenService).validate("reauth-tok", "@alice:gua.global");
                verify(otpService).sendOtp("+12025550199", "1.2.3.4", "en");
                // Success audit uses the masked number, never the plaintext E.164.
                verify(securityAuditLogger).phoneChangeRequested("@alice:gua.global", "••••0199",
                                "1.2.3.4");
                verify(changeNumberSecurityNotifier, never()).onChangeBlockedByCooldown(anyString(), anyString(),
                                org.mockito.ArgumentMatchers.anyLong(), anyString());
        }

        @Test
        void requestPhoneChangeOtpRejectedWithinCooldown() {
                when(userSecurityService.changePhoneCooldownRemainingSeconds("@alice:gua.global")).thenReturn(3600L);

                assertThatThrownBy(() -> service.requestPhoneChangeOtp(
                                "@alice:gua.global", "+12025550199", "reauth-tok", "1.2.3.4", "en"))
                                .isInstanceOf(me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException.class)
                                .extracting(ex -> ((me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException) ex)
                                                .getRetryAfterSeconds())
                                .isEqualTo(3600L);

                verify(reauthTokenService).validate("reauth-tok", "@alice:gua.global");
                // Notifier (audit + deduped device notice) fires before the throw; the plaintext
                // new number is passed to the notifier, which masks it internally.
                verify(changeNumberSecurityNotifier).onChangeBlockedByCooldown("@alice:gua.global", "+12025550199",
                                3600L, "1.2.3.4");
                verify(otpService, never()).sendOtp(anyString(), anyString(), any());
                verify(securityAuditLogger, never()).phoneChangeRequested(anyString(), anyString(), anyString());
        }

        @Test
        void requestPhoneChangeOtpRejectedWithinPostChangeCooldown() {
                // Simulates a user who just changed their number: the post-change cooldown (surfaced
                // through changePhoneCooldownRemainingSeconds) blocks a second change. No OTP is sent.
                when(userSecurityService.changePhoneCooldownRemainingSeconds("@alice:gua.global"))
                                .thenReturn(604800L);

                assertThatThrownBy(() -> service.requestPhoneChangeOtp(
                                "@alice:gua.global", "+12025550199", "reauth-tok", "1.2.3.4", "en"))
                                .isInstanceOf(me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException.class)
                                .extracting(ex -> ((me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException) ex)
                                                .getRetryAfterSeconds())
                                .isEqualTo(604800L);

                verify(otpService, never()).sendOtp(anyString(), anyString(), any());
                verify(securityAuditLogger, never()).phoneChangeRequested(anyString(), anyString(), anyString());
        }

        @Test
        void requestPhoneChangeOtpRejectedWhenNewPhoneLinkedToAnotherAccount() {
                String userId = "@alice:gua.global";
                String newPhone = "+12025550199";
                String newDigest = "taken-digest";
                DirectoryEntry other = DirectoryEntry.builder()
                                .phoneDigest(newDigest)
                                .userId("@bob:gua.global")
                                .build();

                when(userSecurityService.changePhoneCooldownRemainingSeconds(userId)).thenReturn(0L);
                when(phoneNumberHasher.digest(newPhone)).thenReturn(newDigest);
                when(directoryService.findByDigest(newDigest)).thenReturn(Optional.of(other));

                assertThatThrownBy(() -> service.requestPhoneChangeOtp(
                                userId, newPhone, "reauth-tok", "1.2.3.4", "en"))
                                .isInstanceOf(PhoneAlreadyLinkedException.class);

                // The collision is caught at the request step: no SMS is ever dispatched.
                verify(reauthTokenService).validate("reauth-tok", userId);
                verify(otpService, never()).sendOtp(anyString(), anyString(), any());
                verify(securityAuditLogger, never()).phoneChangeRequested(anyString(), anyString(), anyString());
        }
}
