package me.sarahlacerda.gua.identityservice.service;

import static me.sarahlacerda.gua.identityservice.service.ReviewLoginTest.OTHER_PHONE;
import static me.sarahlacerda.gua.identityservice.service.ReviewLoginTest.REVIEW_CODE;
import static me.sarahlacerda.gua.identityservice.service.ReviewLoginTest.REVIEW_CODE_HASH;
import static me.sarahlacerda.gua.identityservice.service.ReviewLoginTest.REVIEW_PHONE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;

/**
 * The store review login as {@link OtpService} applies it: the sign-in send and verify for the
 * one configured number, and nothing anywhere else.
 */
@ExtendWith(MockitoExtension.class)
class OtpServiceReviewLoginTest {

    private static final String CODE_KEY = "otp:code:" + REVIEW_PHONE;
    private static final String ATTEMPTS_KEY = "otp:attempts:" + REVIEW_PHONE;
    private static final String BINDING_KEY = "otp:review-login:" + REVIEW_PHONE;
    private static final String FAILURES_KEY = "otp:review-login-failures:" + REVIEW_PHONE;
    /** The random code a review send stores, which nobody is ever sent. */
    private static final String ISSUED = "482913";

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private OtpCodeGenerator codeGenerator;
    @Mock
    private SmsSender smsSender;
    @Mock
    private SmsSendGuard sendGuard;
    @Mock
    private DirectoryService directory;
    @Mock
    private PhoneNumberHasher hasher;

    private final IdentityServiceProperties properties = new IdentityServiceProperties();
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final List<Duration> waits = new ArrayList<>();
    /** Every bcrypt check against the review code's hash, whatever its answer. */
    private final AtomicInteger reviewCodeChecks = new AtomicInteger();
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void captureLogs() {
        logs = new ListAppender<>();
        logs.start();
        reviewLogger().addAppender(logs);
        otpLogger().addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        reviewLogger().detachAppender(logs);
        otpLogger().detachAppender(logs);
        // Neither the code nor its hash nor the whole number is ever written to a log.
        assertThat(logs.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
                .doesNotContain(REVIEW_CODE)
                .doesNotContain(REVIEW_CODE_HASH)
                .doesNotContain(REVIEW_PHONE));
    }

    private OtpService otpService(ReviewLoginProperties reviewProperties) {
        ReviewLogin reviewLogin = new ReviewLogin(reviewProperties, new PhoneNumberNormalizer(),
                new PhoneNumberMasker(), metrics, directory, hasher, waits::add, new BCryptPasswordEncoder() {
                    @Override
                    public boolean matches(CharSequence rawPassword, String encodedPassword) {
                        reviewCodeChecks.incrementAndGet();
                        return super.matches(rawPassword, encodedPassword);
                    }
                });
        return new OtpService(redisTemplate, properties, codeGenerator, smsSender, sendGuard, metrics, reviewLogin);
    }

    private OtpService enabled() {
        return otpService(ReviewLoginTest.enabled(REVIEW_PHONE, REVIEW_CODE_HASH));
    }

    // -------------------- off --------------------

    @Nested
    class Disabled {

        @Test
        void theReviewNumberIsTextedARandomCodeLikeAnyOther() {
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(codeGenerator.generateNumericCode(6)).thenReturn(ISSUED);

            otpService(ReviewLoginProperties.off()).sendLoginOtp(REVIEW_PHONE, "127.0.0.1", null);

            verify(valueOperations).set(CODE_KEY, ISSUED, properties.getOtp().getTtl());
            verify(smsSender).send(eq(REVIEW_PHONE), eq(
                    "Your Gua verification code is 482913. Never share this code with anyone. Gua support will never ask you for it."));
            verify(valueOperations, never()).set(eq(BINDING_KEY), anyString(), any(Duration.class));
            assertThat(waits).isEmpty();
            assertThat(logs.list).isEmpty();
            assertThat(metrics.find("gua.identity.review.login").counters()).isEmpty();
        }

        @Test
        void theReviewCodeIsJustAWrongGuess() {
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
            when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);

            assertThatThrownBy(() -> otpService(ReviewLoginProperties.off()).verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                    .isInstanceOf(InvalidOtpException.class);

            verify(valueOperations, never()).get(BINDING_KEY);
            verify(valueOperations, never()).get(FAILURES_KEY);
            verify(valueOperations, never()).increment(FAILURES_KEY);
            verify(redisTemplate, never()).delete(CODE_KEY);
            assertThat(reviewCodeChecks).hasValue(0);
        }

        @Test
        void noSignInVerifyPaysForABcryptCheck() {
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            when(valueOperations.get("otp:code:" + OTHER_PHONE)).thenReturn("777777");
            when(valueOperations.increment("otp:attempts:" + OTHER_PHONE)).thenReturn(1L, 2L);
            OtpService otpService = otpService(ReviewLoginProperties.off());

            assertThatThrownBy(() -> otpService.verifyLoginOtp(OTHER_PHONE, "000000"))
                    .isInstanceOf(InvalidOtpException.class);
            otpService.verifyLoginOtp(OTHER_PHONE, "777777");

            assertThat(reviewCodeChecks).hasValue(0);
        }
    }

    // -------------------- send --------------------

    @Test
    void aReviewSignInSendTextsNothingAndOtherwiseDoesWhatAnySendDoes() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(6)).thenReturn(ISSUED);

        enabled().sendLoginOtp(REVIEW_PHONE, "127.0.0.1", "pt-BR");

        verifyNoInteractions(smsSender);
        // The per-number and per-address limits, and no SMS ceiling, since nothing is texted.
        verify(sendGuard).admitWithoutSms(REVIEW_PHONE, "127.0.0.1");
        verifyNoMoreInteractions(sendGuard);
        // A fresh random code with a fresh guess budget and the normal lifetime.
        verify(redisTemplate).delete(ATTEMPTS_KEY);
        verify(valueOperations).set(CODE_KEY, ISSUED, properties.getOtp().getTtl());
        // And the record that this live code is the one a review sign-in issued.
        verify(valueOperations).set(BINDING_KEY, ISSUED, properties.getOtp().getTtl());
        assertThat(waits).hasSize(1);
        assertThat(review(ReviewLogin.Outcome.SENT)).isEqualTo(1.0);
        assertThat(metrics.find("gua.identity.sms.send").counters()).isEmpty();
    }

    @Test
    void aRateLimitedReviewSendIsRefusedLikeAnyOtherAndStoresNothing() {
        doThrow(new OtpRateLimitedException("Too many OTP requests", Duration.ofMinutes(5))).when(sendGuard)
                .admitWithoutSms(REVIEW_PHONE, "127.0.0.1");

        assertThatThrownBy(() -> enabled().sendLoginOtp(REVIEW_PHONE, "127.0.0.1", null))
                .isInstanceOf(OtpRateLimitedException.class);

        verifyNoInteractions(smsSender, codeGenerator, redisTemplate);
        assertThat(waits).isEmpty();
        assertThat(review(ReviewLogin.Outcome.SEND_RATE_LIMITED)).isEqualTo(1.0);
    }

    @Test
    void anyOtherNumberSigningInIsTextedAsBefore() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(6)).thenReturn("777777");

        enabled().sendLoginOtp(OTHER_PHONE, "127.0.0.1", null);

        verify(smsSender).send(eq(OTHER_PHONE), anyString());
        verify(valueOperations).set("otp:code:" + OTHER_PHONE, "777777", properties.getOtp().getTtl());
        verify(valueOperations, never()).set(eq("otp:review-login:" + OTHER_PHONE), anyString(), any(Duration.class));
        assertThat(waits).isEmpty();
        assertThat(metrics.find("gua.identity.review.login").counters()).isEmpty();
    }

    @Test
    void everyOtherPurposeStillTextsTheReviewNumber() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(6)).thenReturn("111111", "222222");
        OtpService otpService = enabled();

        // What reauthentication (the old number in a change of number), the enrollment step-up and
        // POST /otp/send use.
        otpService.sendOtp(REVIEW_PHONE, "127.0.0.1", null);
        // What the PIN change uses.
        otpService.sendScopedOtp(OtpScope.PIN_CHANGE, "chal-1", REVIEW_PHONE, "127.0.0.1", null);

        verify(smsSender, times(2)).send(eq(REVIEW_PHONE), anyString());
        verify(valueOperations, never()).set(eq(BINDING_KEY), anyString(), any(Duration.class));
        assertThat(waits).isEmpty();
    }

    @Test
    void realSendsTeachTheReviewSendHowLongToTake() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(6)).thenReturn("777777", ISSUED);
        OtpService otpService = enabled();

        otpService.sendLoginOtp(OTHER_PHONE, "127.0.0.1", null);
        otpService.sendLoginOtp(REVIEW_PHONE, "127.0.0.1", null);

        // The mocked provider answers at once, so the review send waits about that long, not the
        // default meant for an instance that has not timed a real call yet.
        assertThat(waits).singleElement()
                .satisfies(wait -> assertThat(wait).isLessThan(ReviewLogin.DEFAULT_PROVIDER_LATENCY.dividedBy(2)));
    }

    // -------------------- verify --------------------

    @Test
    void theReviewCodeRedeemsTheCodeAReviewSignInIssued() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);

        enabled().verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE);

        assertThat(reviewCodeChecks).hasValue(1);
        // Single use, exactly like any other code.
        verify(redisTemplate).delete(CODE_KEY);
        verify(redisTemplate).delete(ATTEMPTS_KEY);
        verify(redisTemplate).delete(BINDING_KEY);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isEqualTo(1.0);
        assertThat(verifyCount("valid")).isEqualTo(1.0);
    }

    @Test
    void theIssuedRandomCodeIsNotAcceptedInsteadOfTheReviewCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);

        assertThatThrownBy(() -> enabled().verifyLoginOtp(REVIEW_PHONE, ISSUED))
                .isInstanceOf(InvalidOtpException.class);

        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(1.0);
    }

    @Test
    void theReviewCodeNeedsALiveCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        // Never sent, expired, already used or burned: there is no code to redeem.
        when(valueOperations.get(CODE_KEY)).thenReturn(null);

        assertThatThrownBy(() -> enabled().verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class)
                .hasMessage("Invalid or expired verification code");

        verify(valueOperations, never()).increment(anyString());
        verify(valueOperations, never()).get(BINDING_KEY);
        // Nothing to compare, so no bcrypt either, the same as any number without a live code.
        assertThat(reviewCodeChecks).hasValue(0);
        assertThat(review(ReviewLogin.Outcome.NO_CODE)).isEqualTo(1.0);
    }

    @Test
    void theReviewCodeDoesNotRedeemACodeAnotherFlowTexted() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        // A reauthentication or POST /otp/send replaced the review sign-in's code with one it texted.
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(1.0);

        // The texted code works as it always has, for whoever holds the number.
        otpService.verifyLoginOtp(REVIEW_PHONE, "654321");
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isEqualTo(1.0);
    }

    @Test
    void wrongCodesSpendTheSameBudgetAndTheLastOneBurnsTheCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED, ISSUED, ISSUED, ISSUED, ISSUED, null);
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L, 3L, 4L, 5L);
        OtpService otpService = enabled();

        for (int guess = 1; guess < properties.getOtp().getMaxVerifyAttempts(); guess++) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                    .isInstanceOf(InvalidOtpException.class)
                    .hasMessage("Invalid or expired verification code");
        }
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class)
                .hasMessage("Too many incorrect verification codes; request a new code");

        verify(redisTemplate).delete(CODE_KEY);
        verify(redisTemplate).delete(BINDING_KEY);
        verify(redisTemplate, never()).delete(ATTEMPTS_KEY);
        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(4.0);
        assertThat(review(ReviewLogin.Outcome.EXHAUSTED)).isEqualTo(1.0);
        assertThat(verifyCount("exhausted")).isEqualTo(1.0);

        // Locked like any code: the review code is worthless until a new send.
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        assertThat(review(ReviewLogin.Outcome.NO_CODE)).isEqualTo(1.0);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isZero();
    }

    @Test
    void theReviewCodeAfterFewerThanMaxWrongGuessesIsAccepted() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
        otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE);

        verify(valueOperations, times(2)).increment(ATTEMPTS_KEY);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isEqualTo(1.0);
    }

    @Test
    void noOtherVerifyTakesTheReviewCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
        when(valueOperations.get("otp:code:pin-change:chal-1")).thenReturn("333333");
        when(valueOperations.increment(anyString())).thenReturn(1L);
        OtpService otpService = enabled();

        // Reauthentication, the enrollment step-up and the REST sign-in, right after a review
        // sign-in send.
        assertThatThrownBy(() -> otpService.verifyOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        // The PIN change.
        assertThatThrownBy(() -> otpService.verifyScopedOtp(OtpScope.PIN_CHANGE, "chal-1", REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        verify(valueOperations, never()).get(BINDING_KEY);
        verify(redisTemplate, never()).delete(CODE_KEY);
        // They are not sign-ins: no number pays a bcrypt check on them, so they stay alike too.
        assertThat(reviewCodeChecks).hasValue(0);
        assertThat(metrics.find("gua.identity.review.login").counters()).isEmpty();
    }

    @Test
    void anyOtherNumberVerifiesAsBefore() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("otp:code:" + OTHER_PHONE)).thenReturn("777777");
        when(valueOperations.increment("otp:attempts:" + OTHER_PHONE)).thenReturn(1L, 2L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(OTHER_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        otpService.verifyLoginOtp(OTHER_PHONE, "777777");

        verify(valueOperations, never()).get("otp:review-login:" + OTHER_PHONE);
        assertThat(metrics.find("gua.identity.review.login").counters()).isEmpty();
    }

    /**
     * The review code is checked with bcrypt, which is slow. Every sign-in comparison pays for
     * exactly one check, whatever the number and whatever the live code, so a wrong guess for the
     * review number answers in the same time as one for any other number.
     */
    @Test
    void everySignInComparisonPaysOneBcryptCheckWhateverTheNumber() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED, "654321");
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(FAILURES_KEY)).thenReturn(null);
        when(valueOperations.get("otp:code:" + OTHER_PHONE)).thenReturn("777777");
        when(valueOperations.increment(anyString())).thenReturn(1L);
        OtpService otpService = enabled();

        // The review number, against the code a review sign-in issued.
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
        assertThat(reviewCodeChecks).hasValue(1);
        // The review number, against a code another flow texted.
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
        assertThat(reviewCodeChecks).hasValue(2);
        // Any other number, a wrong guess and then its own code.
        assertThatThrownBy(() -> otpService.verifyLoginOtp(OTHER_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
        assertThat(reviewCodeChecks).hasValue(3);
        otpService.verifyLoginOtp(OTHER_PHONE, "777777");
        assertThat(reviewCodeChecks).hasValue(4);
        // Only the review number's verifies are recorded.
        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(2.0);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isZero();
    }

    // -------------------- the lockout --------------------

    /**
     * A review sign-in's live code, compared with the review code, in a window whose counter reads
     * {@code failures} and then each of {@code later}.
     */
    private void liveReviewCode(String failures, String... later) {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.get(FAILURES_KEY)).thenReturn(failures, later);
    }

    /** Every wrong review code is counted, in a window that starts with the first and is never extended. */
    @Test
    void wrongReviewCodesAreCountedInAWindowFixedFromTheFirst() {
        liveReviewCode(null);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L);
        when(redisTemplate.getExpire(CODE_KEY)).thenReturn(200L);
        when(valueOperations.increment(FAILURES_KEY)).thenReturn(1L, 2L);
        when(redisTemplate.getExpire(FAILURES_KEY)).thenReturn(80_000L);
        OtpService otpService = enabled();

        for (int guess = 0; guess < 2; guess++) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                    .isInstanceOf(InvalidOtpException.class)
                    .hasMessage("Invalid or expired verification code");
        }

        verify(valueOperations, times(2)).increment(FAILURES_KEY);
        verify(redisTemplate, times(1)).expire(FAILURES_KEY, ReviewLogin.LOCKOUT_WINDOW);
        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(2.0);
        assertThat(review(ReviewLogin.Outcome.LOCKED)).isZero();
    }

    /** A counter that lost its expiry gets one back, so no lockout outlives its window. */
    @Test
    void aCounterFoundWithoutAWindowGetsOne() {
        liveReviewCode("7");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);
        when(valueOperations.increment(FAILURES_KEY)).thenReturn(8L);
        when(redisTemplate.getExpire(CODE_KEY)).thenReturn(200L);
        when(redisTemplate.getExpire(FAILURES_KEY)).thenReturn(-1L);

        assertThatThrownBy(() -> enabled().verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);

        verify(redisTemplate).expire(FAILURES_KEY, ReviewLogin.LOCKOUT_WINDOW);
    }

    /**
     * The 20th wrong review code trips the lockout: one ERROR line and one locked count. From then
     * on the right code is refused too, without being compared, while still paying its bcrypt
     * check and answering exactly like a wrong guess.
     */
    @Test
    void theTwentiethWrongReviewCodeLocksItAndEvenTheRightCodeIsRefused() {
        liveReviewCode("19", "20", "20");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L, 3L);
        when(valueOperations.increment(FAILURES_KEY)).thenReturn(20L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class)
                .hasMessage("Invalid or expired verification code");
        assertThat(review(ReviewLogin.Outcome.REJECTED)).isEqualTo(1.0);
        assertThat(review(ReviewLogin.Outcome.LOCKED)).isEqualTo(1.0);
        assertThat(errors()).singleElement().satisfies(event -> assertThat(event.getFormattedMessage())
                .startsWith("Store review login locked for ••••9901"));
        int checksBefore = reviewCodeChecks.get();

        for (String submitted : new String[] { REVIEW_CODE, "000000" }) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, submitted))
                    .isInstanceOf(InvalidOtpException.class)
                    .hasMessage("Invalid or expired verification code");
        }

        // Each refusal paid the bcrypt check a comparison costs, counted, and was not counted again.
        assertThat(reviewCodeChecks).hasValue(checksBefore + 2);
        assertThat(review(ReviewLogin.Outcome.LOCKED)).isEqualTo(3.0);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isZero();
        assertThat(errors()).hasSize(1);
        verify(valueOperations, times(1)).increment(FAILURES_KEY);
        verify(redisTemplate, never()).delete(CODE_KEY);
    }

    /** A refused guess spends the code's budget like any wrong guess, so the fifth burns it as usual. */
    @Test
    void lockedGuessesStillSpendTheCodesBudget() {
        liveReviewCode("20");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L, 3L, 4L, 5L);
        OtpService otpService = enabled();

        for (int guess = 1; guess < properties.getOtp().getMaxVerifyAttempts(); guess++) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                    .hasMessage("Invalid or expired verification code");
        }
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .hasMessage("Too many incorrect verification codes; request a new code");

        verify(redisTemplate).delete(CODE_KEY);
        verify(redisTemplate).delete(BINDING_KEY);
        verify(valueOperations, never()).increment(FAILURES_KEY);
        assertThat(review(ReviewLogin.Outcome.LOCKED)).isEqualTo(5.0);
        assertThat(errors()).isEmpty();
    }

    @Test
    void theRightCodeWorksAgainOnceTheWindowEnds() {
        // Locked, then the counter expired with its window.
        liveReviewCode("20", (String) null);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE);

        assertThat(review(ReviewLogin.Outcome.LOCKED)).isEqualTo(1.0);
        assertThat(review(ReviewLogin.Outcome.ACCEPTED)).isEqualTo(1.0);
    }

    /** The lockout is the review code's: a code texted to the number, and every other number, work as before. */
    @Test
    void aLockoutLeavesTextedCodesAndOtherNumbersAlone() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.get("otp:code:" + OTHER_PHONE)).thenReturn("777777");
        when(valueOperations.increment(anyString())).thenReturn(1L);
        OtpService otpService = enabled();

        otpService.verifyLoginOtp(REVIEW_PHONE, "654321");
        otpService.verifyLoginOtp(OTHER_PHONE, "777777");

        verify(valueOperations, never()).get(FAILURES_KEY);
        verify(valueOperations, never()).get("otp:review-login-failures:" + OTHER_PHONE);
        assertThat(review(ReviewLogin.Outcome.LOCKED)).isZero();
    }

    /** Only wrong review codes count: a wrong guess at a texted code, or at another number's, does not. */
    @Test
    void onlyWrongReviewCodesCount() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.get(BINDING_KEY)).thenReturn(ISSUED);
        when(valueOperations.get("otp:code:" + OTHER_PHONE)).thenReturn("777777");
        when(valueOperations.increment(anyString())).thenReturn(1L);
        OtpService otpService = enabled();

        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> otpService.verifyLoginOtp(OTHER_PHONE, "000000"))
                .isInstanceOf(InvalidOtpException.class);

        verify(valueOperations, never()).increment(FAILURES_KEY);
        verify(valueOperations, never()).increment("otp:review-login-failures:" + OTHER_PHONE);
    }

    // -------------------- helpers --------------------

    private List<ILoggingEvent> errors() {
        return logs.list.stream().filter(event -> event.getLevel() == Level.ERROR).toList();
    }

    private double review(ReviewLogin.Outcome outcome) {
        return ReviewLoginTest.count(metrics, outcome);
    }

    private double verifyCount(String result) {
        Counter counter = metrics.find("gua.identity.otp.verify").tag("result", result).counter();
        return counter == null ? 0.0 : counter.count();
    }

    private static Logger reviewLogger() {
        return (Logger) LoggerFactory.getLogger(ReviewLogin.class);
    }

    private static Logger otpLogger() {
        return (Logger) LoggerFactory.getLogger(OtpService.class);
    }
}
