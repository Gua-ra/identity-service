package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

@ExtendWith(MockitoExtension.class)
class PhoneChangeOtpServiceTest {

    private static final String CHALLENGE = "chal-1";
    private static final String OTP_KEY = "otp:code:change:chal-1";
    private static final String NEW_E164 = "+14155550123";

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
    private PhoneChangeOtpService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        service = new PhoneChangeOtpService(redisTemplate, properties, codeGenerator, smsSender, rateLimiter,
                new SimpleMeterRegistry());
    }

    @Test
    void sendStoresCodeUnderChallengeNamespacedKeyAndTextsNewNumber() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("123456");

        service.send(CHALLENGE, NEW_E164, "1.2.3.4", null);

        // Namespaced per challenge — NOT otp:code:{e164} — so /otp/send cannot race it.
        verify(valueOperations).set(eq(OTP_KEY), eq("123456"), eq(properties.getOtp().getTtl()));
        verify(smsSender).send(eq(NEW_E164),
                eq("Your Gua verification code is 123456. Never share this code with anyone. Gua will never ask you for it."));
        // Send limits keyed on the new number + IP.
        verify(rateLimiter).checkRate(eq("otp:rate:phone:" + NEW_E164),
                eq(properties.getOtp().getMaxRequestsPerPhonePerHour()), org.mockito.ArgumentMatchers.any());
        verify(rateLimiter).checkRate(eq("otp:rate:ip:1.2.3.4"),
                eq(properties.getOtp().getMaxRequestsPerIpPerHour()), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void verifyDeletesKeyOnSuccess() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(OTP_KEY)).thenReturn("654321");

        service.verify(CHALLENGE, "654321");

        verify(redisTemplate).delete(OTP_KEY);
    }

    @Test
    void verifyThrowsOnMismatch() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(OTP_KEY)).thenReturn("654321");

        assertThatThrownBy(() -> service.verify(CHALLENGE, "000000"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void verifyThrowsWhenExpired() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(OTP_KEY)).thenReturn(null);

        assertThatThrownBy(() -> service.verify(CHALLENGE, "654321"))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void discardDeletesOtpKey() {
        service.discard(CHALLENGE);
        verify(redisTemplate).delete(OTP_KEY);
    }
}
