package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.OtpProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.UnsupportedPhoneCountryException;

/**
 * Decides whether one SMS may be sent. Every path that texts a code calls {@link #admit} before
 * the provider: the destination must be in an allowed region, and the per-address, per-number,
 * hourly and daily counters must all have room.
 */
@Component
public class SmsSendGuard {

    static final String IP_KEY_PREFIX = "otp:rate:ip:";
    static final String PHONE_KEY_PREFIX = "otp:rate:phone:";
    static final String HOURLY_KEY = "otp:rate:all:hour";
    static final String DAILY_KEY = "otp:rate:all:day";

    private static final Duration HOUR = Duration.ofHours(1);
    private static final Duration DAY = Duration.ofDays(1);
    private static final PhoneNumberUtil PHONE_NUMBERS = PhoneNumberUtil.getInstance();

    /**
     * KEYS are counters and ARGV holds each one's limit and window in milliseconds. Every counter
     * is read before any is incremented, so a refused send spends no budget. Returns 0 when the
     * send is admitted, otherwise a bitmask of the counters that are full.
     */
    private static final RedisScript<Long> ADMIT = new DefaultRedisScript<>("""
            local full = 0
            local bit = 1
            for i = 1, #KEYS do
              if tonumber(redis.call('GET', KEYS[i]) or '0') >= tonumber(ARGV[2 * i - 1]) then
                full = full + bit
              end
              bit = bit * 2
            end
            if full > 0 then
              return full
            end
            for i = 1, #KEYS do
              if redis.call('INCR', KEYS[i]) == 1 or redis.call('PTTL', KEYS[i]) == -1 then
                redis.call('PEXPIRE', KEYS[i], ARGV[2 * i])
              end
            end
            return 0
            """, Long.class);

    /** Tag values of {@code gua_identity_sms_refused_total{reason}}. */
    public enum Refusal {
        COUNTRY("country"),
        DAILY_CEILING("daily_ceiling"),
        HOURLY_CEILING("hourly_ceiling"),
        IP("ip"),
        PHONE("phone");

        private final String tagValue;

        Refusal(String tagValue) {
            this.tagValue = tagValue;
        }

        public String tagValue() {
            return tagValue;
        }
    }

    private record Counter(String key, int limit, Duration window, Refusal refusal) {
    }

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final MeterRegistry metrics;
    private final Set<String> allowedCountries;

    public SmsSendGuard(StringRedisTemplate redisTemplate, IdentityServiceProperties properties,
            MeterRegistry metrics) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.metrics = metrics;
        this.allowedCountries = allowedCountries(properties.getOtp().getAllowedCountries());
    }

    /**
     * Admits one send to {@code e164PhoneNumber} and counts it, or refuses it and counts nothing.
     *
     * @throws InvalidPhoneNumberException      when the number cannot be parsed
     * @throws UnsupportedPhoneCountryException when its region is not allowed
     * @throws OtpRateLimitedException          when a counter is full, with the wait until the
     *                                          last full one reopens
     */
    public void admit(String e164PhoneNumber, String requesterIp) {
        String region = regionOf(e164PhoneNumber);
        if (region == null || !allowedCountries.contains(region)) {
            refused(Refusal.COUNTRY);
            throw new UnsupportedPhoneCountryException("Verification codes cannot be sent to this country");
        }
        OtpProperties otp = properties.getOtp();
        List<Counter> counters = new ArrayList<>();
        counters.add(new Counter(DAILY_KEY, otp.getMaxSendsPerDay(), DAY, Refusal.DAILY_CEILING));
        counters.add(new Counter(HOURLY_KEY, otp.getMaxSendsPerHour(), HOUR, Refusal.HOURLY_CEILING));
        if (StringUtils.hasText(requesterIp)) {
            counters.add(new Counter(IP_KEY_PREFIX + requesterIp, otp.getMaxRequestsPerIpPerHour(), HOUR, Refusal.IP));
        }
        counters.add(new Counter(PHONE_KEY_PREFIX + e164PhoneNumber, otp.getMaxRequestsPerPhonePerHour(), HOUR,
                Refusal.PHONE));

        List<String> keys = counters.stream().map(Counter::key).toList();
        Object[] limitsAndWindows = counters.stream()
                .flatMap(counter -> Stream.of(String.valueOf(counter.limit()),
                        String.valueOf(counter.window().toMillis())))
                .toArray();
        long full = Objects.requireNonNull(redisTemplate.execute(ADMIT, keys, limitsAndWindows),
                "SMS send limiter returned no reply");
        if (full == 0L) {
            return;
        }

        Refusal refusal = null;
        Duration retryAfter = Duration.ZERO;
        for (int i = 0; i < counters.size(); i++) {
            if ((full & (1L << i)) == 0) {
                continue;
            }
            Counter counter = counters.get(i);
            if (refusal == null) {
                refusal = counter.refusal();
            }
            Duration remaining = remaining(counter);
            if (remaining.compareTo(retryAfter) > 0) {
                retryAfter = remaining;
            }
        }
        refused(refusal);
        boolean ceiling = refusal == Refusal.DAILY_CEILING || refusal == Refusal.HOURLY_CEILING;
        throw new OtpRateLimitedException(
                ceiling ? "Verification codes are temporarily unavailable" : "Too many OTP requests", retryAfter);
    }

    private Duration remaining(Counter counter) {
        Long millis = redisTemplate.getExpire(counter.key(), TimeUnit.MILLISECONDS);
        return millis != null && millis > 0 ? Duration.ofMillis(millis) : counter.window();
    }

    private void refused(Refusal refusal) {
        metrics.counter("gua.identity.sms.refused", "reason", refusal.tagValue()).increment();
    }

    private static String regionOf(String e164PhoneNumber) {
        try {
            return PHONE_NUMBERS.getRegionCodeForNumber(PHONE_NUMBERS.parse(e164PhoneNumber, null));
        } catch (NumberParseException ex) {
            throw new InvalidPhoneNumberException("Phone number could not be parsed");
        }
    }

    private static Set<String> allowedCountries(List<String> configured) {
        Set<String> regions = configured.stream()
                .map(region -> region.trim().toUpperCase(Locale.ROOT))
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> unknown = new TreeSet<>(regions);
        unknown.removeAll(PHONE_NUMBERS.getSupportedRegions());
        if (regions.isEmpty() || !unknown.isEmpty()) {
            throw new IllegalStateException("identity.otp.allowed-countries must list ISO 3166-1 alpha-2 regions"
                    + (unknown.isEmpty() ? "" : "; not recognised: " + String.join(",", unknown)));
        }
        return Set.copyOf(regions);
    }
}
