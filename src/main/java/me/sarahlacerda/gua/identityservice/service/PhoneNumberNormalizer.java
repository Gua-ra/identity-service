package me.sarahlacerda.gua.identityservice.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;

/**
 * Normalizes raw, client-supplied phone numbers to canonical E.164 at the
 * backend boundary so a missing country code can never key OTP / the phone
 * digest under a different value and silently create a duplicate account.
 *
 * <p>
 * A bare national number (no leading {@code +}) is interpreted against the
 * {@value #DEFAULT_REGION} default region — the same region the clients assume
 * (Canada/US, {@code +1}). Anything that cannot be parsed to a valid number is
 * rejected with {@link InvalidPhoneNumberException} rather than being passed
 * through unnormalized.
 */
@Component
public class PhoneNumberNormalizer {

    /** Default region for numbers supplied without a country code (CA/US, +1). */
    static final String DEFAULT_REGION = "CA";

    private final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();

    /**
     * Parses {@code rawPhone} (with the {@value #DEFAULT_REGION} default region for
     * numbers lacking a country code) and returns it in canonical E.164 form.
     *
     * @throws InvalidPhoneNumberException if the input is blank, unparseable, or not
     *                                     a valid phone number
     */
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
