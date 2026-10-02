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

    /**
     * Sends an OTP that belongs to one flow instead of a phone number: the code is written under
     * {@code otp:code:{scope}:{scopeId}}, which the unauthenticated {@code POST /otp/send} cannot write.
     * Send limits, code length, TTL, metrics and the per-code guess budget are the same as {@link #sendOtp}.
     */
    public void sendScopedOtp(OtpScope scope, String scopeId, String e164PhoneNumber, String requesterIp,
            String language) {
        send(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), e164PhoneNumber, requesterIp, language);
    }

    /** Redeems a scoped code under the same per-code guess cap as {@link #verifyOtp}. */
    public void verifyScopedOtp(OtpScope scope, String scopeId, String code) {
        verify(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), code, scope.verifyFlow());
    }

    /**
     * Destroys a scoped code and its guess counter, for a flow that is abandoning the
     * challenge the code belonged to.
     */
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
            // gua_identity_sms_send_total{provider,result}: SMS usage and delivery failures.
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    /**
     * Redeems {@code code} for the phone's live OTP. Every guess is counted per code with an atomic
     * INCR before it is compared, so one code absorbs at most {@code identity.otp.max-verify-attempts}
     * guesses however they are spread or parallelized. The last allowed wrong guess deletes the code,
     * and a guess over the cap is refused without being compared. The counter expires with the code's
     * TTL; only a new send resets it.
     */
    public void verifyOtp(String e164PhoneNumber, String code) {
        verify(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code, OtpVerifyFlow.PHONE);
    }

    private void verify(String codeKey, String attemptsKey, String code, OtpVerifyFlow flow) {
        String storedCode = redisTemplate.opsForValue().get(codeKey);
        if (!StringUtils.hasText(storedCode)) {
            // gua_identity_otp_verify_total{result}: wrong or expired codes.
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
        // gua_identity_otp_verify_total{result="exhausted"}: guesses refused by the cap (brute-force signal).
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

    /**
     * Picks the SMS template for the requested language, keyed by BCP-47 tag. The underscore is folded
     * to a hyphen first because platform locale APIs hand out the ICU identifier ({@code pt_BR}) instead
     * of the language tag ({@code pt-BR}); without the fold a Brazilian caller would be texted in English.
     */
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
