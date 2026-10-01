package me.sarahlacerda.gua.identityservice.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidSignupTokenException;

@Service
public class SignupTokenService {

    private static final String KEY_PREFIX = "signup:token:";
    private static final Duration TTL = Duration.ofMinutes(15);

    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    public SignupTokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String issue(String phone) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(KEY_PREFIX + token, phone, TTL);
        return token;
    }

    public String consume(String token) {
        String phone = peek(token);
        redisTemplate.delete(KEY_PREFIX + token);
        return phone;
    }

    public String peek(String token) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidSignupTokenException("Signup session invalid or expired");
        }
        String phone = redisTemplate.opsForValue().get(KEY_PREFIX + token);
        if (!StringUtils.hasText(phone)) {
            throw new InvalidSignupTokenException("Signup session invalid or expired");
        }
        return phone;
    }
}
