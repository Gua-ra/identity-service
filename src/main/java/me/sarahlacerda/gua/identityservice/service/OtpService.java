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
        // e.g. TwilioSmsSender -> "twilio", LoggingSmsSender -> "logging". Lets the SMS-usage metric
        // distinguish the real provider from the dev logger once real SMS is wired.
        this.smsProvider = SmsSender.providerTag(smsSender);
    }

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        enforceRateLimits(e164PhoneNumber, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = resolveTemplate(language).formatted(code);

        Duration ttl = properties.getOtp().getTtl();
        // A fresh code starts with a fresh guess budget.
        redisTemplate.delete(attemptsKey(e164PhoneNumber));
        redisTemplate.opsForValue().set(codeKey(e164PhoneNumber), code, ttl);
        try {
            smsSender.send(e164PhoneNumber, messageBody);
            // gua_identity_sms_send_total{provider,result} — SMS usage + delivery failures.
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    /**
     * Redeems {@code code} for the phone's live OTP. Every guess is counted per code
     * in Redis before it is compared, so at most {@code identity.otp.max-verify-attempts}
     * guesses are ever compared against one code, however they are spread across
     * addresses and paths or fired in parallel: the count is an atomic INCR, the last
     * allowed guess deletes the code when it is wrong, and a guess whose count overtook
     * the cap is refused without being looked at. The spent counter is left to expire
     * with the code's TTL so a late guess cannot reopen the budget; only a new send,
     * which resets the counter, restores the code. The endpoint limiters bound how
     * fast one address can guess, this bounds how many guesses a code can absorb at all.
     */
    public void verifyOtp(String e164PhoneNumber, String code) {
        String codeKey = codeKey(e164PhoneNumber);
        String attemptsKey = attemptsKey(e164PhoneNumber);
        String storedCode = redisTemplate.opsForValue().get(codeKey);
        if (!StringUtils.hasText(storedCode)) {
            // gua_identity_otp_verify_total{result} — wrong/expired codes (auth friction / abuse signal).
            metrics.counter("gua.identity.otp.verify", "result", "invalid").increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        long attempts = countGuess(codeKey, attemptsKey);
        int maxAttempts = properties.getOtp().getMaxVerifyAttempts();
        if (attempts > maxAttempts) {
            // A parallel guess spent the last slot between this one's GET and INCR.
            throw exhausted(codeKey);
        }
        if (!OtpCodes.matches(storedCode, code)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid").increment();
            if (attempts < maxAttempts) {
                throw new InvalidOtpException("Invalid or expired verification code");
            }
            throw exhausted(codeKey);
        }
        redisTemplate.delete(codeKey);
        redisTemplate.delete(attemptsKey);
        metrics.counter("gua.identity.otp.verify", "result", "valid").increment();
    }

    private long countGuess(String codeKey, String attemptsKey) {
        Long counted = redisTemplate.opsForValue().increment(attemptsKey);
        // The counter never outlives the code it guards.
        redisTemplate.expire(attemptsKey, remainingTtl(codeKey));
        return counted == null ? 1L : counted;
    }

    private InvalidOtpException exhausted(String codeKey) {
        // Only the code goes. Deleting the counter too would hand a guess that fetched the
        // code before the cap tripped a fresh budget starting at 1.
        redisTemplate.delete(codeKey);
        // gua_identity_otp_verify_total{result="exhausted"}: guesses refused by the cap (brute-force signal).
        metrics.counter("gua.identity.otp.verify", "result", "exhausted").increment();
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
