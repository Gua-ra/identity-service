package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;

class PhoneNumberNormalizerTest {

    private final PhoneNumberNormalizer normalizer = new PhoneNumberNormalizer();

    @Test
    void keepsAlreadyE164NumberCanonical() {
        assertThat(normalizer.toE164("+16042251234")).isEqualTo("+16042251234");
    }

    @Test
    void addsDefaultRegionCountryCodeWhenMissing() {
        // National number with no country code resolves against the CA/US (+1) default
        // region, so it can never key OTP / the digest under a different value.
        assertThat(normalizer.toE164("6042251234")).isEqualTo("+16042251234");
    }

    @Test
    void stripsFormattingFromDefaultRegionNumber() {
        assertThat(normalizer.toE164("(604) 225-1234")).isEqualTo("+16042251234");
    }

    @Test
    void rejectsBlankInput() {
        assertThatThrownBy(() -> normalizer.toE164("  "))
                .isInstanceOf(InvalidPhoneNumberException.class);
    }

    @Test
    void rejectsUnparseableInput() {
        assertThatThrownBy(() -> normalizer.toE164("not-a-phone"))
                .isInstanceOf(InvalidPhoneNumberException.class);
    }

    @Test
    void rejectsTooShortNumber() {
        assertThatThrownBy(() -> normalizer.toE164("123"))
                .isInstanceOf(InvalidPhoneNumberException.class);
    }
}
