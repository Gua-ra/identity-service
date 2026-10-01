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
import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;

@Service
public class OtpService {

    private static final String OTP_KEY_PREFIX = "otp:code:";
    private static final String ATTEMPTS_KEY_PREFIX = "otp:attempts:";
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
        this.smsProvider = SmsSender.providerTag(smsSender);
    }

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        send(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), e164PhoneNumber, requesterIp, language);
    }

    public void sendScopedOtp(OtpScope scope, String scopeId, String e164PhoneNumber, String requesterIp,
            String language) {
        send(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), e164PhoneNumber, requesterIp, language);
    }

    public void verifyScopedOtp(OtpScope scope, String scopeId, String code) {
        verify(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), code, scope.verifyFlow());
    }

    public void discardScopedOtp(OtpScope scope, String scopeId) {
        redisTemplate.delete(scopedCodeKey(scope, scopeId));
        redisTemplate.delete(scopedAttemptsKey(scope, scopeId));
    }

    private void send(String codeKey, String attemptsKey, String e164PhoneNumber, String requesterIp,
            String language) {
        enforceRateLimits(e164PhoneNumber, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = resolveTemplate(language).formatted(code);

        Duration ttl = properties.getOtp().getTtl();
        // A fresh code starts with a fresh guess budget.
        redisTemplate.delete(attemptsKey);
        redisTemplate.opsForValue().set(codeKey, code, ttl);
        try {
            smsSender.send(e164PhoneNumber, messageBody);
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    // Each guess is counted with an atomic INCR before comparison, so one code absorbs at most
    // max-verify-attempts guesses.
    public void verifyOtp(String e164PhoneNumber, String code) {
        verify(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code, OtpVerifyFlow.PHONE);
    }

    private void verify(String codeKey, String attemptsKey, String code, OtpVerifyFlow flow) {
        String storedCode = redisTemplate.opsForValue().get(codeKey);
        if (!StringUtils.hasText(storedCode)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", flow.tagValue()).increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        long attempts = countGuess(codeKey, attemptsKey);
        int maxAttempts = properties.getOtp().getMaxVerifyAttempts();
        if (attempts > maxAttempts) {
            // A parallel guess spent the last slot between this one's GET and INCR.
            throw exhausted(codeKey, flow);
        }
        if (!OtpCodes.matches(storedCode, code)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", flow.tagValue()).increment();
            if (attempts < maxAttempts) {
                throw new InvalidOtpException("Invalid or expired verification code");
            }
            throw exhausted(codeKey, flow);
        }
        redisTemplate.delete(codeKey);
        redisTemplate.delete(attemptsKey);
        metrics.counter("gua.identity.otp.verify", "result", "valid", "flow", flow.tagValue()).increment();
    }

    private long countGuess(String codeKey, String attemptsKey) {
        Long counted = redisTemplate.opsForValue().increment(attemptsKey);
        // The counter never outlives the code it guards.
        redisTemplate.expire(attemptsKey, remainingTtl(codeKey));
        return counted == null ? 1L : counted;
    }

    private InvalidOtpException exhausted(String codeKey, OtpVerifyFlow flow) {
        // Only the code is deleted. Deleting the counter would give a racing guess a fresh budget.
        redisTemplate.delete(codeKey);
        metrics.counter("gua.identity.otp.verify", "result", "exhausted", "flow", flow.tagValue()).increment();
        return new InvalidOtpException("Too many incorrect verification codes; request a new code");
    }

    private Duration remainingTtl(String codeKey) {
        Long seconds = redisTemplate.getExpire(codeKey);
        return seconds != null && seconds > 0 ? Duration.ofSeconds(seconds) : properties.getOtp().getTtl();
    }

    private static String codeKey(String e164PhoneNumber) {
        return OTP_KEY_PREFIX + e164PhoneNumber;
    }

    private static String attemptsKey(String e164PhoneNumber) {
        return ATTEMPTS_KEY_PREFIX + e164PhoneNumber;
    }

    private static String scopedCodeKey(OtpScope scope, String scopeId) {
        return OTP_KEY_PREFIX + scope.keySegment() + ":" + scopeId;
    }

    private static String scopedAttemptsKey(OtpScope scope, String scopeId) {
        return ATTEMPTS_KEY_PREFIX + scope.keySegment() + ":" + scopeId;
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

    /** Platform locale APIs hand out pt_BR, so the underscore is folded to a hyphen before matching. */
    private String resolveTemplate(String requestedLanguage) {
        String defaultTemplate = properties.getOtp().getSmsTemplate();
        if (!StringUtils.hasText(requestedLanguage)) {
            return defaultTemplate;
        }

        String normalized = requestedLanguage.trim().toLowerCase(Locale.ROOT).replace('_', '-');
        String template = properties.getOtp().getLocalizedSmsTemplates().get(normalized);
        if (template == null && normalized.contains("-")) {
            String primaryTag = normalized.substring(0, normalized.indexOf('-'));
            template = properties.getOtp().getLocalizedSmsTemplates().get(primaryTag);
        }
        return template != null ? template : defaultTemplate;
    }
}
