package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.ReauthPhoneMismatchException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberNormalizer;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@ExtendWith(MockitoExtension.class)
class AccountReauthServiceTest {

    private static final String USER = "@alice:server";
    private static final String OTHER_USER = "@bob:server";
    private static final String PHONE = "+12025550123";
    private static final String OTHER_PHONE = "+12025550999";
    private static final String DIGEST = "digest-of-alices-number";
    private static final String OTHER_DIGEST = "digest-of-somebody-elses";
    private static final String MISMATCH_KEY = "reauth:phone-mismatch:" + USER;

    @Mock
    private OtpService otpService;

    @Mock
    private DirectoryService directoryService;

    @Mock
    private PhoneNumberNormalizer phoneNumberNormalizer;

    @Mock
    private PhoneNumberHasher phoneNumberHasher;

    @Mock
    private MatrixAdminClient matrixAdminClient;

    @Mock
    private ReauthTokenService reauthTokenService;

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private SecurityAuditLogger auditLogger;

    private IdentityServiceProperties properties;
    private AccountReauthService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        service = new AccountReauthService(otpService, directoryService, phoneNumberNormalizer, phoneNumberHasher,
                matrixAdminClient, reauthTokenService, redisTemplate, auditLogger, properties);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        lenient().when(phoneNumberNormalizer.toE164(PHONE)).thenReturn(PHONE);
        lenient().when(phoneNumberNormalizer.toE164(OTHER_PHONE)).thenReturn(OTHER_PHONE);
        lenient().when(phoneNumberHasher.digest(PHONE)).thenReturn(DIGEST);
        lenient().when(phoneNumberHasher.digest(OTHER_PHONE)).thenReturn(OTHER_DIGEST);
    }

    @Test
    void startSendsTheOtpToTheAccountsOwnNumber() {
        directoryHolds(DIGEST);

        service.startReauth(USER, PHONE, "1.2.3.4", "en-US");

        verify(otpService).sendOtp(PHONE, "1.2.3.4", "en-US");
        verify(valueOperations, never()).set(any(), any());
        verify(valueOperations).decrement(MISMATCH_KEY);
    }

    @Test
    void theAttemptIsReservedBeforeTheNumberIsCompared() {
        directoryHolds(DIGEST);

        service.startReauth(USER, PHONE, "1.2.3.4", null);

        InOrder inOrder = inOrder(valueOperations, directoryService);
        inOrder.verify(valueOperations).increment(MISMATCH_KEY);
        inOrder.verify(directoryService).findByUserId(USER);
    }

    @Test
    void startNormalizesTheSubmittedNumberBeforeComparing() {
        when(phoneNumberNormalizer.toE164("2025550123")).thenReturn(PHONE);
        directoryHolds(DIGEST);

        service.startReauth(USER, "2025550123", "1.2.3.4", null);

        verify(otpService).sendOtp(PHONE, "1.2.3.4", null);
    }

    @Test
    void aNumberThatIsNotTheAccountsIsRefusedWithoutSayingWhose() {
        directoryHolds(DIGEST);
        when(matrixAdminClient.findUserIdByPhone(OTHER_PHONE)).thenReturn(Optional.of(OTHER_USER));

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(ReauthPhoneMismatchException.class)
                .hasMessage("That is not the number on your account.");

        verifyNoInteractions(otpService);
        verify(auditLogger).reauthFailed(USER, "REAUTH_START", "1.2.3.4");
        verify(valueOperations).increment(MISMATCH_KEY);
    }

    @Test
    void anUnknownNumberIsRefusedWithTheSameWords() {
        directoryHolds(DIGEST);
        when(matrixAdminClient.findUserIdByPhone(OTHER_PHONE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(ReauthPhoneMismatchException.class)
                .hasMessage("That is not the number on your account.");
    }

    @Test
    void aDriftedDigestFallsBackToTheHomeserverPhoneBinding() {
        directoryHolds("digest-under-the-old-pepper");
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenReturn(Optional.of(USER));

        service.startReauth(USER, PHONE, "1.2.3.4", null);

        verify(otpService).sendOtp(PHONE, "1.2.3.4", null);
    }

    @Test
    void anUnavailableFallbackRefusesRatherThanAccepts() {
        directoryHolds("digest-under-the-old-pepper");
        when(matrixAdminClient.findUserIdByPhone(PHONE)).thenThrow(new IllegalStateException("admin API 401"));

        assertThatThrownBy(() -> service.startReauth(USER, PHONE, "1.2.3.4", null))
                .isInstanceOf(ReauthPhoneMismatchException.class);
        verifyNoInteractions(otpService);
    }

    @Test
    void aMalformedNumberIsRefusedByTheNormalizerAndCostsNoAttempt() {
        when(phoneNumberNormalizer.toE164("nope")).thenThrow(new InvalidPhoneNumberException("not valid"));

        assertThatThrownBy(() -> service.startReauth(USER, "nope", "1.2.3.4", null))
                .isInstanceOf(InvalidPhoneNumberException.class);

        verifyNoInteractions(otpService);
        verify(valueOperations, never()).increment(MISMATCH_KEY);
    }

    @Test
    void theAttemptCapRefusesFurtherGuesses() {
        when(valueOperations.increment(MISMATCH_KEY))
                .thenReturn((long) properties.getSecurity().getMaxReauthPhoneAttemptsPerHour() + 1);

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(RateLimiterException.class)
                .hasMessageNotContaining(USER);

        verifyNoInteractions(otpService);
        verifyNoInteractions(directoryService);
        verifyNoInteractions(matrixAdminClient);
    }

    @Test
    void theAttemptCapAlsoRefusesTheCorrectNumber() {
        when(valueOperations.increment(MISMATCH_KEY)).thenReturn(6L);

        assertThatThrownBy(() -> service.startReauth(USER, PHONE, "1.2.3.4", null))
                .isInstanceOf(RateLimiterException.class);
        verifyNoInteractions(otpService);
    }

    @Test
    void anUnreachableCounterRefusesTheAttempt() {
        when(valueOperations.increment(MISMATCH_KEY))
                .thenThrow(new QueryTimeoutException("redis unavailable"));

        assertThatThrownBy(() -> service.startReauth(USER, PHONE, "1.2.3.4", null))
                .isInstanceOf(RateLimiterException.class)
                .hasMessageNotContaining(USER);
        verifyNoInteractions(directoryService);
        verifyNoInteractions(otpService);
    }

    @Test
    void theFirstMismatchOpensTheHourWindow() {
        directoryHolds(DIGEST);
        when(matrixAdminClient.findUserIdByPhone(OTHER_PHONE)).thenReturn(Optional.empty());
        when(valueOperations.increment(MISMATCH_KEY)).thenReturn(1L);

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(ReauthPhoneMismatchException.class);

        verify(redisTemplate).expire(MISMATCH_KEY, Duration.ofHours(1));
    }

    @Test
    void aLaterAttemptInsideTheBudgetArmsTheWindowToo() {
        directoryHolds(DIGEST);
        when(matrixAdminClient.findUserIdByPhone(OTHER_PHONE)).thenReturn(Optional.empty());
        when(valueOperations.increment(MISMATCH_KEY)).thenReturn(3L);

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(ReauthPhoneMismatchException.class);

        verify(redisTemplate).expire(MISMATCH_KEY, Duration.ofHours(1));
    }

    @Test
    void aRefusedAttemptDoesNotPushTheWindowOut() {
        when(valueOperations.increment(MISMATCH_KEY)).thenReturn(9L);

        assertThatThrownBy(() -> service.startReauth(USER, OTHER_PHONE, "1.2.3.4", null))
                .isInstanceOf(RateLimiterException.class);

        verify(redisTemplate, never()).expire(any(), any(Duration.class));
    }

    @Test
    void verifyIssuesTheOperationScopedTokenAfterTheOtp() {
        directoryHolds(DIGEST);
        when(reauthTokenService.issue(USER, ReauthOperation.PHONE_CHANGE)).thenReturn("opaque-token");

        String token = service.verifyReauth(USER, PHONE, "123456", ReauthOperation.PHONE_CHANGE, "1.2.3.4");

        verify(otpService).verifyOtp(PHONE, "123456");
        assertThat(token).isEqualTo("opaque-token");
        verify(valueOperations).decrement(MISMATCH_KEY);
    }

    @Test
    void verifyRefusesANumberThatIsNotTheAccountsBeforeTouchingTheOtp() {
        directoryHolds(DIGEST);
        when(matrixAdminClient.findUserIdByPhone(OTHER_PHONE)).thenReturn(Optional.of(OTHER_USER));

        assertThatThrownBy(
                () -> service.verifyReauth(USER, OTHER_PHONE, "123456", ReauthOperation.DEACTIVATE, "1.2.3.4"))
                .isInstanceOf(ReauthPhoneMismatchException.class);

        verifyNoInteractions(otpService);
        verifyNoInteractions(reauthTokenService);
        verify(auditLogger).reauthFailed(USER, "DEACTIVATE", "1.2.3.4");
    }

    @Test
    void verifyDoesNotIssueATokenWhenTheOtpIsWrong() {
        directoryHolds(DIGEST);
        org.mockito.Mockito.doThrow(new InvalidOtpException("bad"))
                .when(otpService).verifyOtp(eq(PHONE), eq("000000"));

        assertThatThrownBy(() -> service.verifyReauth(USER, PHONE, "000000", ReauthOperation.DEACTIVATE, "1.2.3.4"))
                .isInstanceOf(InvalidOtpException.class);
        verifyNoInteractions(reauthTokenService);
    }

    @Test
    void verifyPhoneOtpProvesTheNumberWithoutMintingAToken() {
        directoryHolds(DIGEST);

        service.verifyPhoneOtp(USER, PHONE, "123456", "ENROLL_STEP_UP", "1.2.3.4");

        verify(otpService).verifyOtp(PHONE, "123456");
        verifyNoInteractions(reauthTokenService);
    }

    @Test
    void requireValidReauthDelegatesToTokenService() {
        when(reauthTokenService.consume("opaque-token", USER, ReauthOperation.PHONE_CHANGE)).thenReturn(USER);

        service.requireValidReauth(USER, "opaque-token", ReauthOperation.PHONE_CHANGE);

        verify(reauthTokenService).consume("opaque-token", USER, ReauthOperation.PHONE_CHANGE);
    }

    @Test
    void requireValidReauthRejectsBlankToken() {
        assertThatThrownBy(() -> service.requireValidReauth(USER, " ", ReauthOperation.PHONE_CHANGE))
                .isInstanceOf(InvalidReauthTokenException.class);
        verifyNoInteractions(reauthTokenService);
    }

    private void directoryHolds(String phoneDigest) {
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().userId(USER).phoneDigest(phoneDigest).build()));
    }
}
