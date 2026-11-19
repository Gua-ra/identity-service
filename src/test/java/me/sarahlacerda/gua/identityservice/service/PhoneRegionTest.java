package me.sarahlacerda.gua.identityservice.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PhoneRegionTest {

    @ParameterizedTest
    @CsvSource({
            "+46701234567, SE",
            "+4520123456, DK",
            "+447400123456, GB",
            "+4915123456789, DE",
            "+38343201234, XK",
            "+15062345678, CA",
            "+5511961234567, BR",
    })
    void namesTheCountryOfAnE164Number(String phone, String region) {
        assertEquals(region, PhoneRegion.of(phone));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "not a number", "+999123" })
    void answersUnknownWhenTheNumberHasNoCountry(String phone) {
        assertEquals("unknown", PhoneRegion.of(phone));
    }
}
