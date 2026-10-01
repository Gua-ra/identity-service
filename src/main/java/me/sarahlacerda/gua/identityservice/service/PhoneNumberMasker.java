package me.sarahlacerda.gua.identityservice.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class PhoneNumberMasker {

    private static final String BULLETS = "\u2022\u2022\u2022\u2022";
    private static final int VISIBLE_DIGITS = 4;

    public String mask(String phone) {
        if (!StringUtils.hasText(phone) || phone.length() < VISIBLE_DIGITS) {
            return null;
        }
        return BULLETS + phone.substring(phone.length() - VISIBLE_DIGITS);
    }
}
