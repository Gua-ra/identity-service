package me.sarahlacerda.gua.identityservice.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;

/** A number without a country code is parsed against DEFAULT_REGION, the region the clients assume. */
@Component
public class PhoneNumberNormalizer {

    static final String DEFAULT_REGION = "CA";

    private final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();

    public String toE164(String rawPhone) {
        if (!StringUtils.hasText(rawPhone)) {
            throw new InvalidPhoneNumberException("Phone number is required");
        }
        PhoneNumber parsed;
        try {
            parsed = phoneNumberUtil.parse(rawPhone.trim(), DEFAULT_REGION);
        } catch (NumberParseException ex) {
            throw new InvalidPhoneNumberException("Phone number could not be parsed");
        }
        if (!phoneNumberUtil.isValidNumber(parsed)) {
            throw new InvalidPhoneNumberException("Phone number is not valid");
        }
        return phoneNumberUtil.format(parsed, PhoneNumberFormat.E164);
    }
}
