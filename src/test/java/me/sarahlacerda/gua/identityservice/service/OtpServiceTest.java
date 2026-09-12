package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    private static final String PHONE = "+12025550123";
    private static final String CODE_KEY = "otp:code:+12025550123";
    private static final String ATTEMPTS_KEY = "otp:attempts:+12025550123";

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private OtpCodeGenerator codeGenerator;

    @Mock
    private SmsSender smsSender;

    @Mock
    private RateLimiter rateLimiter;

    private IdentityServiceProperties properties;
    private SimpleMeterRegistry metrics;
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        metrics = new SimpleMeterRegistry();
        otpService = new OtpService(redisTemplate, properties, codeGenerator, smsSender, rateLimiter, metrics);
    }

    @Test
    void sendOtpStoresCodeAndSendsSms() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("123456");

        otpService.sendOtp("+12025550123", "127.0.0.1", null);

        verify(rateLimiter).checkRate("otp:rate:phone:+12025550123",
                properties.getOtp().getMaxRequestsPerPhonePerHour(), Duration.ofHours(1));
        verify(rateLimiter).checkRate("otp:rate:ip:127.0.0.1", properties.getOtp().getMaxRequestsPerIpPerHour(),
                Duration.ofHours(1));
        verify(valueOperations).set(eq("otp:code:+12025550123"), eq("123456"), eq(properties.getOtp().getTtl()));
        verify(smsSender).send("+12025550123",
                "Your Gua verification code is 123456. Never share this code with anyone. Gua will never ask you for it.");
    }

    @Test
    void sendOtpResetsTheGuessBudgetBeforeStoringTheNewCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("123456");

        otpService.sendOtp(PHONE, "127.0.0.1", null);

        // Counter gone first, so the new code never inherits the old code's wrong guesses.
        InOrder inOrder = Mockito.inOrder(redisTemplate, valueOperations);
        inOrder.verify(redisTemplate).delete(ATTEMPTS_KEY);
        inOrder.verify(valueOperations).set(eq(CODE_KEY), eq("123456"), eq(properties.getOtp().getTtl()));
    }

    @Test
    void verifyOtpCountsTheGuessThenRemovesTheCodeOnSuccess() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);

        otpService.verifyOtp(PHONE, "654321");

        // Counted before it is compared: a right guess spends a slot like a wrong one.
        InOrder inOrder = Mockito.inOrder(redisTemplate, valueOperations);
        inOrder.verify(valueOperations).increment(ATTEMPTS_KEY);
        inOrder.verify(redisTemplate).delete(CODE_KEY);
        inOrder.verify(redisTemplate).delete(ATTEMPTS_KEY);
        assertThat(count("valid")).isEqualTo(1.0);
    }

    @Test
    void verifyOtpThrowsOnMismatch() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("otp:code:+12025550123")).thenReturn("654321");

        assertThatThrownBy(() -> otpService.verifyOtp("+12025550123", "123456"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void verifyOtpSucceedsWhenTheRightCodeFollowsFewerThanMaxWrongGuesses() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L, 3L, 4L, 5L);

        for (int guess = 1; guess < properties.getOtp().getMaxVerifyAttempts(); guess++) {
            assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "000000")).isInstanceOf(InvalidOtpException.class);
        }
        verify(redisTemplate, never()).delete(CODE_KEY);

        // The right code takes the fifth and last slot, which is within the budget.
        otpService.verifyOtp(PHONE, "654321");

        verify(valueOperations, times(5)).increment(ATTEMPTS_KEY);
        verify(redisTemplate).delete(CODE_KEY);
        verify(redisTemplate).delete(ATTEMPTS_KEY);
        assertThat(count("valid")).isEqualTo(1.0);
        assertThat(count("invalid")).isEqualTo(4.0);
        assertThat(count("exhausted")).isZero();
    }

    @Test
    void verifyOtpDeletesTheCodeOnTheMaxWrongGuess() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321", "654321", "654321", "654321", "654321", null);
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L, 3L, 4L, 5L);

        for (int guess = 1; guess <= properties.getOtp().getMaxVerifyAttempts(); guess++) {
            assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "000000")).isInstanceOf(InvalidOtpException.class);
        }

        verify(redisTemplate).delete(CODE_KEY);
        // The spent counter stays until it expires, so a guess that fetched the code
        // before the cap tripped cannot start over at 1.
        verify(redisTemplate, never()).delete(ATTEMPTS_KEY);
        assertThat(count("exhausted")).isEqualTo(1.0);
        assertThat(count("invalid")).isEqualTo(5.0);

        // The right code is now worthless: only a new send restores it, and nothing is
        // counted against a code that no longer exists.
        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "654321")).isInstanceOf(InvalidOtpException.class);
        verify(valueOperations, times(5)).increment(ATTEMPTS_KEY);
        assertThat(count("valid")).isZero();
    }

    @Test
    void verifyOtpRefusesAGuessThatOvertookTheCapWithoutComparing() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        // A parallel guess spent the fifth slot between this call's GET and INCR.
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(6L);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "654321"))
                .isInstanceOf(InvalidOtpException.class)
                .hasMessage("Too many incorrect verification codes; request a new code");

        // Even the right code is refused unseen: nothing was compared, so nothing succeeded.
        verify(redisTemplate).delete(CODE_KEY);
        verify(redisTemplate, never()).delete(ATTEMPTS_KEY);
        assertThat(count("valid")).isZero();
        assertThat(count("invalid")).isZero();
        assertThat(count("exhausted")).isEqualTo(1.0);
    }

    @Test
    void verifyOtpHonoursTheConfiguredCap() {
        properties.getOtp().setMaxVerifyAttempts(2);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L, 2L);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "111111")).isInstanceOf(InvalidOtpException.class);
        verify(redisTemplate, never()).delete(CODE_KEY);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "222222")).isInstanceOf(InvalidOtpException.class);
        verify(redisTemplate).delete(CODE_KEY);
    }

    @Test
    void wrongGuessCounterExpiresWithTheCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);
        when(redisTemplate.getExpire(CODE_KEY)).thenReturn(90L);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "000000")).isInstanceOf(InvalidOtpException.class);

        verify(redisTemplate).expire(ATTEMPTS_KEY, Duration.ofSeconds(90));
    }

    @Test
    void wrongGuessCounterFallsBackToTheConfiguredTtl() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);
        when(redisTemplate.getExpire(CODE_KEY)).thenReturn(null);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "000000")).isInstanceOf(InvalidOtpException.class);

        verify(redisTemplate).expire(ATTEMPTS_KEY, properties.getOtp().getTtl());
    }

    @Test
    void verifyOtpCountsAMissingCodeAsAWrongGuess() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn("654321");
        when(valueOperations.increment(ATTEMPTS_KEY)).thenReturn(1L);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, null)).isInstanceOf(InvalidOtpException.class);

        verify(valueOperations).increment(ATTEMPTS_KEY);
    }

    @Test
    void verifyOtpCountsNothingAgainstAnExpiredCode() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(CODE_KEY)).thenReturn(null);

        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, "654321")).isInstanceOf(InvalidOtpException.class);

        verify(valueOperations, never()).increment(anyString());
        assertThat(count("invalid")).isEqualTo(1.0);
    }

    @Test
    void sendOtpTransformsRateLimiterExceptions() {
        Mockito.doThrow(new RateLimiterException("fail")).when(rateLimiter)
                .checkRate(eq("otp:rate:phone:+12025550123"), anyInt(), any(Duration.class));

        assertThatThrownBy(() -> otpService.sendOtp("+12025550123", null, null))
                .isInstanceOf(OtpRateLimitedException.class);
    }

    @Test
    void sendOtpSkipsIpRateLimitWhenIpMissing() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("999999");

        otpService.sendOtp("+12025550123", null, null);

        verify(rateLimiter).checkRate("otp:rate:phone:+12025550123",
                properties.getOtp().getMaxRequestsPerPhonePerHour(), Duration.ofHours(1));
        verifyNoMoreInteractions(rateLimiter);
    }

    @Test
    void sendOtpUsesLocalizedTemplateWhenAvailable() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("777777");
        properties.getOtp().getLocalizedSmsTemplates().put("pt-br", "Seu código Gua é %s");

        otpService.sendOtp("+5511999999999", "200.200.200.200", "pt-BR");

        verify(smsSender).send("+5511999999999", "Seu código Gua é 777777");
    }

    @Test
    void sendOtpFallsBackToPrimaryLanguageTag() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("333333");
        properties.getOtp().getLocalizedSmsTemplates().put("pt", "Código Gua: %s");

        otpService.sendOtp("+5511888888888", "198.51.100.1", "pt-BR");

        verify(smsSender).send("+5511888888888", "Código Gua: 333333");
    }

    // -------------------- scoped codes --------------------

    @Test
    void aScopedSendWritesOutsideTheKeyThePublicSendOwns() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("123456");

        otpService.sendScopedOtp(OtpScope.PIN_CHANGE, "chal-1", PHONE, "127.0.0.1", null);

        // Keyed to the challenge, so POST /otp/send, which only ever writes the per-phone key,
        // can neither plant a code here ahead of the flow nor have one of its codes accepted.
        verify(valueOperations).set(eq("otp:code:pin-change:chal-1"), eq("123456"),
                eq(properties.getOtp().getTtl()));
        verify(valueOperations, never()).set(eq(CODE_KEY), anyString(), any());
        verify(redisTemplate).delete("otp:attempts:pin-change:chal-1");
        verify(redisTemplate, never()).delete(ATTEMPTS_KEY);
        // Same send limits as the public path: namespacing the code is not an exemption.
        verify(rateLimiter).checkRate("otp:rate:phone:" + PHONE,
                properties.getOtp().getMaxRequestsPerPhonePerHour(), Duration.ofHours(1));
        verify(rateLimiter).checkRate("otp:rate:ip:127.0.0.1", properties.getOtp().getMaxRequestsPerIpPerHour(),
                Duration.ofHours(1));
        verify(smsSender).send(eq(PHONE), anyString());
    }

    @Test
    void aPublicCodeDoesNotSatisfyAScopedVerify() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("otp:code:pin-reset:@user:gua.global")).thenReturn(null);

        // A code the public send minted for this number is presented to the reset flow.
        assertThatThrownBy(() -> otpService.verifyScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "654321"))
                .isInstanceOf(InvalidOtpException.class);

        // The per-phone key is never even read, so whatever lives under it is irrelevant.
        verify(valueOperations, never()).get(CODE_KEY);
        // And nothing is counted: there is no scoped code to guess at.
        verify(valueOperations, never()).increment(anyString());
    }

    @Test
    void aScopedCodeIsSingleUseAndCarriesTheSameGuessBudget() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        String codeKey = "otp:code:pin-reset:@user:gua.global";
        String attemptsKey = "otp:attempts:pin-reset:@user:gua.global";
        when(valueOperations.get(codeKey)).thenReturn("654321");
        when(valueOperations.increment(attemptsKey)).thenReturn(1L, 2L, 3L, 4L, 5L);

        for (int guess = 1; guess <= properties.getOtp().getMaxVerifyAttempts(); guess++) {
            assertThatThrownBy(() -> otpService.verifyScopedOtp(OtpScope.PIN_RESET, "@user:gua.global", "000000"))
                    .isInstanceOf(InvalidOtpException.class);
        }

        // The cap burns the scoped code exactly as it burns a per-phone one, and the spent
        // counter is left to expire with it.
        verify(redisTemplate).delete(codeKey);
        verify(redisTemplate, never()).delete(attemptsKey);
        assertThat(count("exhausted")).isEqualTo(1.0);
    }

    @Test
    void discardingAScopedChallengeTakesItsCodeAndItsCounter() {
        otpService.discardScopedOtp(OtpScope.PIN_CHANGE, "chal-1");

        verify(redisTemplate).delete("otp:code:pin-change:chal-1");
        verify(redisTemplate).delete("otp:attempts:pin-change:chal-1");
        verify(redisTemplate, never()).delete(CODE_KEY);
    }

    private double count(String result) {
        Counter counter = metrics.find("gua.identity.otp.verify").tag("result", result).counter();
        return counter == null ? 0.0 : counter.count();
    }
}
