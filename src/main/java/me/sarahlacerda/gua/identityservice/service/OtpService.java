package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.Locale;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;

@Service
public class OtpService {

    private static final String OTP_KEY_PREFIX = "otp:code:";
    private static final String PHONE_RATE_KEY_PREFIX = "otp:rate:phone:";
    private static final String IP_RATE_KEY_PREFIX = "otp:rate:ip:";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final OtpCodeGenerator codeGenerator;
    private final SmsSender smsSender;
    private final RateLimiter rateLimiter;
    private final MeterRegistry metrics;
    private final String smsProvider;

    public OtpService(
        StringRedisTemplate redisTemplate,
        IdentityServiceProperties properties,
        OtpCodeGenerator codeGenerator,
        SmsSender smsSender,
        RateLimiter rateLimiter,
        MeterRegistry metrics
    ) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.codeGenerator = codeGenerator;
        this.smsSender = smsSender;
        this.rateLimiter = rateLimiter;
        this.metrics = metrics;
        // e.g. TwilioSmsSender -> "twilio", LoggingSmsSender -> "logging". Lets the SMS-usage metric
        // distinguish the real provider from the dev logger once real SMS is wired.
        this.smsProvider = smsSender.getClass().getSimpleName()
            .replace("SmsSender", "").toLowerCase(java.util.Locale.ROOT);
    }

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        enforceRateLimits(e164PhoneNumber, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = resolveTemplate(language).formatted(code);

        String key = OTP_KEY_PREFIX + e164PhoneNumber;
        Duration ttl = properties.getOtp().getTtl();
        redisTemplate.opsForValue().set(key, code, ttl);
        try {
            smsSender.send(e164PhoneNumber, messageBody);
            // gua_identity_sms_send_total{provider,result} — SMS usage + delivery failures.
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    public void verifyOtp(String e164PhoneNumber, String code) {
        String key = OTP_KEY_PREFIX + e164PhoneNumber;
        String storedCode = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(storedCode) || !storedCode.equals(code)) {
            // gua_identity_otp_verify_total{result} — wrong/expired codes (auth friction / abuse signal).
            metrics.counter("gua.identity.otp.verify", "result", "invalid").increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        redisTemplate.delete(key);
        metrics.counter("gua.identity.otp.verify", "result", "valid").increment();
    }

    private void enforceRateLimits(String e164PhoneNumber, String requesterIp) {
        Duration window = Duration.ofHours(1);
        try {
            rateLimiter.checkRate(PHONE_RATE_KEY_PREFIX + e164PhoneNumber, properties.getOtp().getMaxRequestsPerPhonePerHour(), window);
            if (StringUtils.hasText(requesterIp)) {
                rateLimiter.checkRate(IP_RATE_KEY_PREFIX + requesterIp, properties.getOtp().getMaxRequestsPerIpPerHour(), window);
            }
        } catch (RateLimiterException ex) {
            throw new OtpRateLimitedException("Too many OTP requests", ex);
        }
    }

    private String resolveTemplate(String requestedLanguage) {
        String defaultTemplate = properties.getOtp().getSmsTemplate();
        if (!StringUtils.hasText(requestedLanguage)) {
            return defaultTemplate;
        }

        String normalized = requestedLanguage.trim().toLowerCase(Locale.ROOT);
        String template = properties.getOtp().getLocalizedSmsTemplates().get(normalized);
        if (template == null && normalized.contains("-")) {
            String primaryTag = normalized.substring(0, normalized.indexOf('-'));
            template = properties.getOtp().getLocalizedSmsTemplates().get(primaryTag);
        }
        return template != null ? template : defaultTemplate;
    }
}
