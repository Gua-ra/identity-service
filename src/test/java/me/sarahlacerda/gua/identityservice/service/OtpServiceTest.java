package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

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
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        otpService = new OtpService(redisTemplate, properties, codeGenerator, smsSender, rateLimiter);
    }

    @Test
    void sendOtpStoresCodeAndSendsSms() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(codeGenerator.generateNumericCode(properties.getOtp().getCodeLength())).thenReturn("123456");

        otpService.sendOtp("+12025550123", "127.0.0.1", null);

        verify(rateLimiter).checkRate("otp:rate:phone:+12025550123", properties.getOtp().getMaxRequestsPerPhonePerHour(), Duration.ofHours(1));
        verify(rateLimiter).checkRate("otp:rate:ip:127.0.0.1", properties.getOtp().getMaxRequestsPerIpPerHour(), Duration.ofHours(1));
        verify(valueOperations).set(eq("otp:code:+12025550123"), eq("123456"), eq(properties.getOtp().getTtl()));
        verify(smsSender).send("+12025550123", "Your Gua verification code is 123456");
    }

    @Test
    void verifyOtpRemovesStoredCodeOnSuccess() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("otp:code:+12025550123")).thenReturn("654321");

        otpService.verifyOtp("+12025550123", "654321");

        verify(redisTemplate).delete("otp:code:+12025550123");
    }

    @Test
    void verifyOtpThrowsOnMismatch() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("otp:code:+12025550123")).thenReturn("654321");

        assertThatThrownBy(() -> otpService.verifyOtp("+12025550123", "123456"))
            .isInstanceOf(InvalidOtpException.class);
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

        verify(rateLimiter).checkRate("otp:rate:phone:+12025550123", properties.getOtp().getMaxRequestsPerPhonePerHour(), Duration.ofHours(1));
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
}
