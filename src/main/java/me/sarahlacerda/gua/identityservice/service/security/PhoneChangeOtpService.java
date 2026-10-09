package me.sarahlacerda.gua.identityservice.service.security;

import java.util.Locale;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.OtpCodes;
import me.sarahlacerda.gua.identityservice.service.SmsSendGuard;
import me.sarahlacerda.gua.identityservice.service.SmsSender;
import me.sarahlacerda.gua.identityservice.service.SmsTemplates;

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
 * Sends pass the same {@link SmsSendGuard} as OtpService and count in the same SMS metrics.
 * </p>
 */
@Service
public class PhoneChangeOtpService {

    private static final String OTP_KEY_PREFIX = "otp:code:change:";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final OtpCodeGenerator codeGenerator;
    private final SmsSender smsSender;
    private final SmsSendGuard sendGuard;
    private final MeterRegistry metrics;
    private final String smsProvider;

    public PhoneChangeOtpService(
            StringRedisTemplate redisTemplate,
            IdentityServiceProperties properties,
            OtpCodeGenerator codeGenerator,
            SmsSender smsSender,
            SmsSendGuard sendGuard,
            MeterRegistry metrics) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.codeGenerator = codeGenerator;
        this.smsSender = smsSender;
        this.sendGuard = sendGuard;
        this.metrics = metrics;
        this.smsProvider = smsSender.getClass().getSimpleName()
                .replace("SmsSender", "").toLowerCase(Locale.ROOT);
    }

    /**
     * Generates a fresh OTP for {@code challengeId}, stores it under the
     * challenge-namespaced key, and texts it to {@code newE164}.
     */
    public void send(String challengeId, String newE164, String requesterIp, String language) {
        sendGuard.admit(newE164, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = SmsTemplates.forLanguage(properties.getOtp(), language).formatted(code);

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
     * is missing, expired, or wrong. The comparison is constant-time; the caller
     * ({@code PhoneChangeService}) owns the per-challenge attempt cap.
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

    private String otpKey(String challengeId) {
        return OTP_KEY_PREFIX + challengeId;
    }
}
