package me.sarahlacerda.gua.identityservice.service.security;

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
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.SmsSender;

/**
 * Sends and verifies the OTP for the <em>new</em> number in a phone-change flow.
 *
 * <p>
 * Deliberately a sibling of {@link me.sarahlacerda.gua.identityservice.service.OtpService}
 * rather than a reuse of it: the code is namespaced per <b>challenge</b>
 * ({@code otp:code:change:{challengeId}}) instead of per phone
 * ({@code otp:code:{e164}}). That isolation means the public {@code /otp/send}
 * endpoint — which writes {@code otp:code:{e164}} — can neither overwrite nor race
 * the change OTP, and an attacker cannot pre-seed a code for the target number.
 * The per-phone / per-IP send rate limits and SMS metrics mirror OtpService so
 * abuse accounting stays consistent.
 * </p>
 */
@Service
public class PhoneChangeOtpService {

    private static final String OTP_KEY_PREFIX = "otp:code:change:";
    private static final String PHONE_RATE_KEY_PREFIX = "otp:rate:phone:";
    private static final String IP_RATE_KEY_PREFIX = "otp:rate:ip:";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final OtpCodeGenerator codeGenerator;
    private final SmsSender smsSender;
    private final RateLimiter rateLimiter;
    private final MeterRegistry metrics;
    private final String smsProvider;

    public PhoneChangeOtpService(
            StringRedisTemplate redisTemplate,
            IdentityServiceProperties properties,
            OtpCodeGenerator codeGenerator,
            SmsSender smsSender,
            RateLimiter rateLimiter,
            MeterRegistry metrics) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.codeGenerator = codeGenerator;
        this.smsSender = smsSender;
        this.rateLimiter = rateLimiter;
        this.metrics = metrics;
        this.smsProvider = smsSender.getClass().getSimpleName()
                .replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }

    /**
     * Generates a fresh OTP for {@code challengeId}, stores it under the
     * challenge-namespaced key, and texts it to {@code newE164}. Applies the same
     * per-phone/per-IP send limits as the public OTP path.
     */
    public void send(String challengeId, String newE164, String requesterIp, String language) {
        enforceRateLimits(newE164, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = resolveTemplate(language).formatted(code);

        redisTemplate.opsForValue().set(otpKey(challengeId), code, properties.getOtp().getTtl());
        try {
            smsSender.send(newE164, messageBody);
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    /**
     * Verifies {@code code} against the challenge-namespaced OTP. Single-use:
     * deletes the key on success. Throws {@link InvalidOtpException} when the code
     * is missing, expired, or wrong — the caller owns the per-challenge attempt cap.
     */
    public void verify(String challengeId, String code) {
        String key = otpKey(challengeId);
        String storedCode = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(storedCode) || !storedCode.equals(code)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", "phone-change").increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        redisTemplate.delete(key);
        metrics.counter("gua.identity.otp.verify", "result", "valid", "flow", "phone-change").increment();
    }

    /** Destroys the OTP for a challenge (used when the attempt cap is reached or the challenge is abandoned). */
    public void discard(String challengeId) {
        redisTemplate.delete(otpKey(challengeId));
    }

    private void enforceRateLimits(String e164PhoneNumber, String requesterIp) {
        Duration window = Duration.ofHours(1);
        try {
            rateLimiter.checkRate(PHONE_RATE_KEY_PREFIX + e164PhoneNumber,
                    properties.getOtp().getMaxRequestsPerPhonePerHour(), window);
            if (StringUtils.hasText(requesterIp)) {
                rateLimiter.checkRate(IP_RATE_KEY_PREFIX + requesterIp,
                        properties.getOtp().getMaxRequestsPerIpPerHour(), window);
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

    private String otpKey(String challengeId) {
        return OTP_KEY_PREFIX + challengeId;
    }
}
