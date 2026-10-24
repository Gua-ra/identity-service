package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;
import java.util.Locale;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.OtpCodes;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.SmsSender;
import me.sarahlacerda.gua.identityservice.service.SmsTemplates;

/**
 * Sends and verifies the OTP for the new number in a phone-change flow.
 *
 * <p>The code is keyed per challenge ({@code otp:code:change:{challengeId}}) instead of per phone
 * ({@code otp:code:{e164}}), so the public {@code /otp/send} endpoint can neither overwrite nor
 * pre-seed it. Send rate limits and SMS metrics mirror
 * {@link me.sarahlacerda.gua.identityservice.service.OtpService}.
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
        String messageBody = SmsTemplates.forLanguage(properties.getOtp(), language).formatted(code);

        redisTemplate.opsForValue().set(otpKey(challengeId), code, properties.getOtp().getTtl());
        try {
            smsSender.send(newE164, messageBody);
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (SmsRefusedException ex) {
            // Nothing was texted: the code reached nobody, and the send costs no budget.
            redisTemplate.delete(otpKey(challengeId));
            refundRateLimits(newE164, requesterIp);
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            metrics.counter("gua.identity.sms.refused", "reason", ex.getReason().tagValue()).increment();
            throw ex;
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    /**
     * Verifies {@code code} against the challenge-namespaced OTP. Single-use: deletes the key on
     * success. Throws {@link InvalidOtpException} when the code is missing, expired or wrong. The
     * comparison is constant-time; the caller owns the per-challenge attempt cap.
     */
    public void verify(String challengeId, String code) {
        String key = otpKey(challengeId);
        String storedCode = redisTemplate.opsForValue().get(key);
        if (!StringUtils.hasText(storedCode) || !OtpCodes.matches(storedCode, code)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", OtpVerifyFlow.PHONE_CHANGE.tagValue()).increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        redisTemplate.delete(key);
        metrics.counter("gua.identity.otp.verify", "result", "valid", "flow", OtpVerifyFlow.PHONE_CHANGE.tagValue()).increment();
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

    private void refundRateLimits(String e164PhoneNumber, String requesterIp) {
        rateLimiter.refund(PHONE_RATE_KEY_PREFIX + e164PhoneNumber);
        if (StringUtils.hasText(requesterIp)) {
            rateLimiter.refund(IP_RATE_KEY_PREFIX + requesterIp);
        }
    }

    private String otpKey(String challengeId) {
        return OTP_KEY_PREFIX + challengeId;
    }
}
