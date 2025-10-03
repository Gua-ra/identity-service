package me.sarahlacerda.gua.identityservice.service;

import java.security.SecureRandom;

import org.springframework.stereotype.Component;

@Component
public class OtpCodeGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateNumericCode(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(secureRandom.nextInt(10));
        }
        return builder.toString();
    }
}
