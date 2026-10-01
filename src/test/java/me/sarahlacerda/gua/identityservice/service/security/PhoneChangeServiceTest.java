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
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
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
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@ExtendWith(MockitoExtension.class)
class PhoneChangeServiceTest {

    private static final String USER = "@alice:gua.global";
    private static final String NEW_RAW = "4155550123";
    private static final String NEW_E164 = "+14155550123";
    private static final String CHALLENGE = "chal-1";
    private static final String CHALLENGE_KEY = "phone:change:chal-1";
    // Old enough that the fresh-factor hold has expired.
    private static final Instant REGISTERED_LONG_AGO = Instant.now().minus(Duration.ofDays(400));

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
                new AuthFactorPolicy(userSecurityService, passkeyService),
                passkeyService,
                phoneChangeOtpService,
                phoneNumberNormalizer,
                phoneNumberHasher,
                new PhoneNumberMasker(),
                directoryService,
                phoneDirectorySwapService,
                matrixProvisioningService,
                tokenRevocationService,
                auditLogger,
                deviceNotificationService);
    }

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
        verify(valueOperations).set(eq("phone:change:" + start.challengeId()),
                eq(USER + "|" + NEW_E164 + "|0"), any());
        verify(auditLogger).phoneChangeStarted(eq(USER), anyString(), anyString(), eq("1.2.3.4"));
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

    @Test
    void startBlocksAccountWithNeitherPinNorPasskey() {
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(StepUpRequiredException.class);

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
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER, REGISTERED_LONG_AGO));
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, null,
                "pk-stepup", credential, "1.2.3.4", "en");

        verify(passkeyService).finishStepUpAssertion("pk-stepup", credential);
        verify(passkeyService, never()).finishAuthentication(anyString(), any());
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

    @Test
    void startNeverSpendsASignInAssertionAsTheStepUp() {
        when(userSecurityService.hasPin(USER)).thenReturn(false);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        doThrow(new me.sarahlacerda.gua.identityservice.exception.LoginFlowException(
                org.springframework.http.HttpStatus.FORBIDDEN, "passkey_user_verification_required", "no uv"))
                .when(passkeyService).finishStepUpAssertion("pk-stepup", credential);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, "pk-stepup", credential,
                "1.2.3.4", "en"))
                .isInstanceOf(me.sarahlacerda.gua.identityservice.exception.LoginFlowException.class);

        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verifyNoInteractions(phoneChangeOtpService);
        verifyNoInteractions(deviceNotificationService);
    }

    @Test
    void startRefusesAnAssertionThatResolvesToAnotherAccountBeforeAcceptingIt() {
        when(userSecurityService.hasPin(USER)).thenReturn(false);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@mallory:gua.global", REGISTERED_LONG_AGO));

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, "pk-stepup", credential,
                "1.2.3.4", "en"))
                .isInstanceOf(InvalidPinException.class);

        verify(auditLogger).reauthFailed(USER, ReauthOperation.PHONE_CHANGE.name(), "1.2.3.4");
        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verifyNoInteractions(phoneChangeOtpService);
    }

    @Test
    void aVerifiedPasskeySettlesTheStepUpWithoutThePinOnAnAccountThatHasBoth() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER, REGISTERED_LONG_AGO));
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, null,
                "pk-stepup", credential, "1.2.3.4", "en");

        verify(userSecurityService, never()).validatePinOrThrow(anyString(), anyString());
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

    @Test
    void theFreshPinHoldNeverAppliesToAnAccountThatProvedAPasskey() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER, REGISTERED_LONG_AGO));
        primeSuccessfulStart();

        service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, "pk-stepup", credential, "1.2.3.4", "en");

        verify(userSecurityService, never()).enforcePhoneChangePinHold(anyString());
        verify(userSecurityService).enforcePhoneChangeCooldown(USER);
    }

    @Test
    void thePasskeyIsTriedBeforeThePinRatherThanAfterIt() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        doThrow(new me.sarahlacerda.gua.identityservice.exception.LoginFlowException(
                org.springframework.http.HttpStatus.FORBIDDEN, "passkey_user_verification_required", "no uv"))
                .when(passkeyService).finishStepUpAssertion("pk-stepup", credential);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", "pk-stepup",
                credential, "1.2.3.4", "en"))
                .isInstanceOf(me.sarahlacerda.gua.identityservice.exception.LoginFlowException.class);

        verify(userSecurityService, never()).validatePinOrThrow(anyString(), anyString());
        verifyNoInteractions(phoneChangeOtpService);
    }

    @Test
    void theOwnershipCheckStillRunsBeforeTheAssertionIsAcceptedOnAnAccountWithAPin() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@mallory:example.test", REGISTERED_LONG_AGO));

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", "pk-stepup",
                credential, "1.2.3.4", "en"))
                .isInstanceOf(InvalidPinException.class);

        verify(userSecurityService, never()).validatePinOrThrow(anyString(), anyString());
        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verifyNoInteractions(phoneChangeOtpService);
    }

    @Test
    void anAccountThatOffersNoAssertionStillGetsThroughOnItsPin() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456",
                null, null, "1.2.3.4", "en");

        verify(passkeyService, never()).hasPasskey(anyString());
        verify(userSecurityService).validatePinOrThrow(USER, "123456");
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

    @Test
    void startRefusesAPinThatWasMintedInsideTheHold() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        doThrow(new TwoFactorCooldownException("too new", 600))
                .when(userSecurityService).enforcePhoneChangePinHold(USER);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(TwoFactorCooldownException.class);

        verify(userSecurityService).validatePinOrThrow(USER, "123456");
        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verify(phoneNumberNormalizer, never()).toE164(anyString());
        verifyNoInteractions(phoneChangeOtpService);
        verifyNoInteractions(deviceNotificationService);
    }

    @Test
    void startChecksTheHoldOnlyAfterThePinItself() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        doThrow(new InvalidPinException("wrong")).when(userSecurityService).validatePinOrThrow(USER, "000000");

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, "000000", null, null, "1.2.3.4",
                "en"))
                .isInstanceOf(InvalidPinException.class);

        verify(userSecurityService, never()).enforcePhoneChangePinHold(anyString());
    }

    @Test
    void startRunsTheHoldAndTheChangeCooldownAsSeparateRefusals() {
        when(userSecurityService.hasPin(USER)).thenReturn(true);
        primeSuccessfulStart();

        service.startPhoneNumberChange(USER, "tok", NEW_RAW, "123456", null, null, "1.2.3.4", "en");

        InOrder order = inOrder(userSecurityService);
        order.verify(userSecurityService).validatePinOrThrow(USER, "123456");
        order.verify(userSecurityService).enforcePhoneChangePinHold(USER);
        order.verify(userSecurityService).enforcePhoneChangeCooldown(USER);
    }

    @Test
    void startRefusesAPasskeyThatWasRegisteredInsideTheHold() {
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        Instant enrolledMinutesAgo = Instant.now().minus(Duration.ofMinutes(5));
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER, enrolledMinutesAgo));
        doThrow(new TwoFactorCooldownException("too new", 600))
                .when(userSecurityService).enforceFreshFactorHold(enrolledMinutesAgo);

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, "pk-stepup", credential,
                "1.2.3.4", "en"))
                .isInstanceOf(TwoFactorCooldownException.class);

        verify(userSecurityService, never()).enforcePhoneChangeCooldown(anyString());
        verify(phoneNumberNormalizer, never()).toE164(anyString());
        verifyNoInteractions(phoneChangeOtpService);
        verifyNoInteractions(deviceNotificationService);
    }

    @Test
    void startWeighsTheCredentialsAgeOnlyAfterItIsKnownToBeTheCallersOwn() {
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication("@mallory:example.test", REGISTERED_LONG_AGO));

        assertThatThrownBy(() -> service.startPhoneNumberChange(USER, "tok", NEW_RAW, null, "pk-stepup", credential,
                "1.2.3.4", "en"))
                .isInstanceOf(InvalidPinException.class);

        verify(userSecurityService, never()).enforceFreshFactorHold(any());
    }

    @Test
    void startLetsAnEstablishedPasskeySettleTheStepUpAtOnce() {
        JsonNode credential = JsonNodeFactory.instance.objectNode();
        when(passkeyService.finishStepUpAssertion("pk-stepup", credential))
                .thenReturn(new PasskeyService.PasskeyAuthentication(USER, REGISTERED_LONG_AGO));
        primeSuccessfulStart();

        PhoneChangeService.PhoneChangeStart start = service.startPhoneNumberChange(USER, "tok", NEW_RAW, null,
                "pk-stepup", credential, "1.2.3.4", "en");

        verify(userSecurityService).enforceFreshFactorHold(REGISTERED_LONG_AGO);
        verify(userSecurityService, never()).validatePinOrThrow(anyString(), anyString());
        verify(phoneChangeOtpService).send(start.challengeId(), NEW_E164, "1.2.3.4", "en");
    }

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

        verify(valueOperations).set(eq(CHALLENGE_KEY), eq(USER + "|" + NEW_E164 + "|2"), any());
        verify(redisTemplate, never()).delete(CHALLENGE_KEY);
        verify(phoneChangeOtpService, never()).discard(CHALLENGE);
        verify(auditLogger).phoneChangeOtpFailed(USER, 2, "9.9.9.9");
    }

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

    @Test
    void completeDelegatesAtomicSwapToTransactionalBean() {
        primeSuccessfulComplete();

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        verify(phoneDirectorySwapService).swap(USER, NEW_E164);
        verify(redisTemplate).delete(CHALLENGE_KEY);
    }

    @Test
    void completeRunsPostCommitSideEffectsEachOnceInOrder() {
        primeSuccessfulComplete();

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        InOrder inOrder = inOrder(phoneDirectorySwapService, tokenRevocationService,
                auditLogger, deviceNotificationService);
        inOrder.verify(phoneDirectorySwapService).swap(USER, NEW_E164);
        inOrder.verify(tokenRevocationService).revokeAllTokens(USER);
        inOrder.verify(auditLogger).phoneChangeCompleted(eq(USER), anyString());
        inOrder.verify(deviceNotificationService).notifyPhoneChanged(eq(USER), anyString());
    }

    @Test
    void completeTouchesTheHomeserverOnlyToBindTheNewNumber() {
        primeSuccessfulComplete();

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        verify(matrixProvisioningService).ensureExclusivePhoneBinding(USER, NEW_E164);
        verifyNoMoreInteractions(matrixProvisioningService);
    }

    @Test
    void completeStillRevokesTokensWhenNotifyFails() {
        primeSuccessfulComplete();
        doThrow(new RuntimeException("push down")).when(deviceNotificationService)
                .notifyPhoneChanged(anyString(), anyString());

        service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4");

        verify(tokenRevocationService).revokeAllTokens(USER);
    }

    @Test
    void completePropagatesConflictFromSwapAndDoesNotRevokeTokens() {
        primeSuccessfulComplete();
        doThrow(new PhoneAlreadyLinkedException("Phone number already linked to another account"))
                .when(phoneDirectorySwapService).swap(USER, NEW_E164);

        assertThatThrownBy(() -> service.completePhoneNumberChange(USER, CHALLENGE, "123456", "1.2.3.4"))
                .isInstanceOf(PhoneAlreadyLinkedException.class);

        verify(tokenRevocationService, never()).revokeAllTokens(anyString());
        verify(redisTemplate, never()).delete(CHALLENGE_KEY);
    }

    private void primeSuccessfulStart() {
        when(phoneNumberNormalizer.toE164(NEW_RAW)).thenReturn(NEW_E164);
        when(phoneNumberHasher.digest(NEW_E164)).thenReturn("new-digest");
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest("old-digest").userId(USER).build()));
        when(directoryService.findMaskedPhoneByUserId(USER)).thenReturn(java.util.Optional.of("••••9999"));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    private void primeSuccessfulComplete() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CHALLENGE_KEY)).thenReturn(USER + "|" + NEW_E164 + "|0");
        org.mockito.Mockito.lenient().when(directoryService.findMaskedPhoneByUserId(USER))
                .thenReturn(java.util.Optional.of("••••9999"));
    }
}
