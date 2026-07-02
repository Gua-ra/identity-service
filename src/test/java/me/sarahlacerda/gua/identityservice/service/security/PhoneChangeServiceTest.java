package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneChangeChallengeException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.routing.ResolverDirectoryClient;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@ExtendWith(MockitoExtension.class)
class PhoneChangeServiceTest {

    private static final String USER = "@alice:gua.global";
    private static final String NEW_RAW = "4155550123";
    private static final String NEW_E164 = "+14155550123";
    private static final String CHALLENGE = "chal-1";
    private static final String CHALLENGE_KEY = "phone:change:chal-1";

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private AccountReauthService reauthService;
    @Mock
    private UserSecurityService userSecurityService;
    @Mock
    private PasskeyService passkeyService;
    @Mock
    private PhoneChangeOtpService phoneChangeOtpService;
    @Mock
    private PhoneNumberNormalizer phoneNumberNormalizer;
    @Mock
    private PhoneNumberHasher phoneNumberHasher;
    @Mock
    private DirectoryService directoryService;
    @Mock
    private PhoneDirectorySwapService phoneDirectorySwapService;
    @Mock
    private MatrixProvisioningService matrixProvisioningService;
    @Mock
    private ResolverDirectoryClient resolverDirectoryClient;
    @Mock
    private TokenRevocationService tokenRevocationService;
    @Mock
    private SecurityAuditLogger auditLogger;
    @Mock
    private DeviceNotificationService deviceNotificationService;

    private IdentityServiceProperties properties;
    private PhoneChangeService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        service = new PhoneChangeService(
                properties,
                redisTemplate,
                reauthService,
                userSecurityService,
                passkeyService,
                phoneChangeOtpService,
                phoneNumberNormalizer,
                phoneNumberHasher,
                new PhoneNumberMasker(),
                directoryService,
                phoneDirectorySwapService,
                matrixProvisioningService,
                resolverDirectoryClient,
                tokenRevocationService,
                auditLogger,
                deviceNotificationService);
    }

    // -------------------- /start --------------------

    @Test
    void startRequiresPhoneChangeScopedReauthBeforeAnyEffect() {
        doThrow(new me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException("bad"))
                .when(reauthService).requireValidReauth(USER, "tok", ReauthOperation.PHONE_CHANGE);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException.class);

        verify(reauthService).requireValidReauth(USER, "tok", ReauthOperation.PHONE_CHANGE);
        verify(auditLogger).reauthFailed(USER, ReauthOperation.PHONE_CHANGE.name(), "1.2.3.4");
        verifyNoInteractions(phoneChangeOtpService);
        verify(phoneNumberNormalizer, never()).toE164(anyString());
    }

    @Test
    void startEnforcesPinWhenAccountHasPin() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        doThrow(new InvalidPinException("wrong")).when(userSecurityService).validatePinOrThrow(USER, "000000");

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "000000", null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(InvalidPinException.class);

        verify(userSecurityService).validatePinOrThrow(USER, "000000");
        verify(auditLogger).reauthFailed(USER, ReauthOperation.PHONE_CHANGE.name(), "1.2.3.4");
        verifyNoInteractions(phoneChangeOtpService);
    }

    @Test
    void startNormalizesStoresChallengeAuditsAndAlertsOldNumber() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        when(phoneNumberNormalizer.toE164(NEW_RAW)).thenReturn(NEW_E164);
        when(phoneNumberHasher.digest(NEW_E164)).thenReturn("new-digest");
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("old-digest").userId(USER).build()));
        when(directoryService.findMaskedPhoneByUserId(USER)).thenReturn(java.util.Optional.of("••••9999"));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", null,
                null, "1.2.3.4", "en");

        verify(userSecurityService).validatePinOrThrow(USER, "123456");
        verify(userSecurityService).enforcePhoneChangeCooldown(USER);
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
        // Challenge stored as userId|newE164|0
        verify(valueOperations).set(eq("phone:change:" + start.challengeId()),
                eq(USER + "|" + NEW_E164 + "|0"), any());
        verify(auditLogger).phoneChangeStarted(eq(USER), anyString(), anyString(), eq("1.2.3.4"));
        // Old number alerted out of band.
        verify(deviceNotificationService).notifyPhoneChangeInitiated(eq(USER), anyString(), anyString());
    }

    @Test
    void startRejectsEqualsCurrentBeforeSendingOtp() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        when(phoneNumberNormalizer.toE164(NEW_RAW)).thenReturn(NEW_E164);
        when(phoneNumberHasher.digest(NEW_E164)).thenReturn("same-digest");
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("same-digest").userId(USER).build()));

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(PhoneAlreadyLinkedException.class);

        verifyNoInteractions(phoneChangeOtpService);
    }

    // -------------------- /start: step-up hard requirement --------------------

    @Test
    void startBlocksAccountWithNeitherPinNorPasskey() {
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(StepUpRequiredException.class);

        // Hard block per product decision (2026-07-02): no token-only fallback. The
        // reauth token is still spent, the failure is audited, and nothing else runs.
        verify(auditLogger).reauthFailed(USER, ReauthOperation.PHONE_CHANGE.name(), "1.2.3.4");
        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verify(phoneNumberNormalizer, never()).toE164(anyString());
        verifyNoInteractions(phoneChangeOtpService);
        verifyNoInteractions(deviceNotificationService);
    }

    @Test
    void startAllowsPinOnlyAccount() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456",
                null, null, "1.2.3.4", "en");

        verify(userSecurityService).validatePinOrThrow(USER, "123456");
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

    @Test
    void startAllowsPasskeyOnlyAccount() {
        when(userSecurityService.hasPin(USER)).thenReturn(false);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishAuthentication("pk-sess", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER));
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, null,
                "pk-sess", credential, "1.2.3.4", "en");

        verify(passkeyService).finishAuthentication("pk-sess", credential);
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

    // -------------------- /complete: brute-force cap --------------------

    @Test
    void completeFifthWrongOtpDeletesBothOtpKeyAndChallengeIpIndependent() {
        properties.getSecurity().setMaxPhoneChangeOtpAttempts(5);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        // attempts already at 4 -> this failure is the 5th.
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn(USER + "|" + NEW_E164 + "|4");
        doThrow(new InvalidOtpException("bad")).when(phoneChangeOtpService).verify(CHALLENGE, "000000");

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "000000", "9.9.9.9"))
                .isInstanceOf(InvalidOtpException.class);

        verify(redisTemplate).delete(CHALLENGE_KEY);
        verify(phoneChangeOtpService).discard(CHALLENGE);
        verify(auditLogger).phoneChangeOtpFailed(USER, 5, "9.9.9.9");
        // No swap.
        verify(matrixProvisioningService, never()).ensureExclusivePhoneBinding(anyString(), anyString());
    }

    @Test
    void completeWrongOtpUnderCapIncrementsCounterWithoutConsumingChallenge() {
        properties.getSecurity().setMaxPhoneChangeOtpAttempts(5);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn(USER + "|" + NEW_E164 + "|1");
        when(redisTemplate.getExpire(CHALLENGE_KEY)).thenReturn(120L);
        doThrow(new InvalidOtpException("bad")).when(phoneChangeOtpService).verify(CHALLENGE, "000000");

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "000000", "9.9.9.9"))
                .isInstanceOf(InvalidOtpException.class);

        // Counter persisted as 2; challenge NOT deleted, OTP NOT discarded.
        verify(valueOperations).set(eq(CHALLENGE_KEY), eq(USER + "|" + NEW_E164 + "|2"), any());
        verify(redisTemplate, never()).delete(CHALLENGE_KEY);
        verify(phoneChangeOtpService, never()).discard(CHALLENGE);
        verify(auditLogger).phoneChangeOtpFailed(USER, 2, "9.9.9.9");
    }

    // -------------------- /complete: validation --------------------

    @Test
    void completeRejectsMissingChallenge() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn(null);

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4"))
                .isInstanceOf(InvalidPhoneChangeChallengeException.class);
    }

    @Test
    void completeRejectsChallengeOwnedByAnotherUserAndDestroysIt() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn("@bob:gua.global|" + NEW_E164 + "|0");

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4"))
                .isInstanceOf(InvalidPhoneChangeChallengeException.class);

        verify(redisTemplate).delete(CHALLENGE_KEY);
        verify(phoneChangeOtpService).discard(CHALLENGE);
    }

    // -------------------- /complete: happy path + carry-forward --------------------

    @Test
    void completeDelegatesAtomicSwapToTransactionalBean() {
        primeSuccessfulComplete();

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        // The swap runs in a separate bean so the @Transactional proxy engages
        // (a self-call would make it non-atomic). Internals are covered by
        // PhoneDirectorySwapServiceTest.
        verify(phoneDirectorySwapService).swap(USER, NEW_E164);
        verify(redisTemplate).delete(CHALLENGE_KEY); // challenge fully spent
    }

    @Test
    void completeRunsPostCommitSideEffectsEachOnceInOrder() {
        primeSuccessfulComplete();
        when(matrixProvisioningService.getLinkedPhonesExcluding(USER, NEW_E164))
                .thenReturn(List.of("+15145550000"));

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        InOrder inOrder = inOrder(phoneDirectorySwapService, resolverDirectoryClient, tokenRevocationService,
                auditLogger, deviceNotificationService);
        inOrder.verify(phoneDirectorySwapService).swap(USER, NEW_E164);
        inOrder.verify(resolverDirectoryClient).registerPhone(NEW_E164);
        inOrder.verify(resolverDirectoryClient).unregisterPhone("+15145550000");
        inOrder.verify(tokenRevocationService).revokeAllTokens(USER);
        inOrder.verify(auditLogger).phoneChangeCompleted(eq(USER), anyString());
        inOrder.verify(deviceNotificationService).notifyPhoneChanged(eq(USER), anyString());
    }

    @Test
    void completeStillRevokesTokensWhenNotifyOrResolverFails() {
        primeSuccessfulComplete();
        when(matrixProvisioningService.getLinkedPhonesExcluding(USER, NEW_E164))
                .thenReturn(List.of("+15145550000"));
        doThrow(new RuntimeException("resolver down")).when(resolverDirectoryClient).registerPhone(NEW_E164);
        doThrow(new RuntimeException("resolver down")).when(resolverDirectoryClient).unregisterPhone(anyString());
        doThrow(new RuntimeException("push down")).when(deviceNotificationService)
                .notifyPhoneChanged(anyString(), anyString());

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        // The session-takeover control must fire even though side effects failed.
        verify(tokenRevocationService).revokeAllTokens(USER);
    }

    @Test
    void completePropagatesConflictFromSwapAndDoesNotRevokeTokens() {
        primeSuccessfulComplete();
        doThrow(new PhoneAlreadyLinkedException("Phone number already linked to another account"))
                .when(phoneDirectorySwapService).swap(USER, NEW_E164);

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4"))
                .isInstanceOf(PhoneAlreadyLinkedException.class);

        // Swap rolled back -> no post-commit side effects, challenge not spent.
        verify(tokenRevocationService, never()).revokeAllTokens(anyString());
        verify(redisTemplate, never()).delete(CHALLENGE_KEY);
    }

    /** Shared stubs for a /start that passes step-up and reaches the OTP send. */
    private void primeSuccessfulStart() {
        when(phoneNumberNormalizer.toE164(NEW_RAW)).thenReturn(NEW_E164);
        when(phoneNumberHasher.digest(NEW_E164)).thenReturn("new-digest");
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("old-digest").userId(USER).build()));
        when(directoryService.findMaskedPhoneByUserId(USER)).thenReturn(java.util.Optional.of("••••9999"));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    /**
     * Shared stubs for a /complete that passes OTP verification. Lenient where a
     * given test does not exercise every collaborator. The atomic swap itself is a
     * void mock (no-op by default) — its internals are tested in
     * PhoneDirectorySwapServiceTest.
     */
    private void primeSuccessfulComplete() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn(USER + "|" + NEW_E164 + "|0");
        // phoneChangeOtpService.verify(...) returns void on success (no stub -> no throw).
        org.mockito.Mockito.lenient().when(directoryService.findMaskedPhoneByUserId(USER))
                .thenReturn(java.util.Optional.of("••••9999"));
        org.mockito.Mockito.lenient().when(matrixProvisioningService.getLinkedPhonesExcluding(USER, NEW_E164))
                .thenReturn(List.of());
    }
}
