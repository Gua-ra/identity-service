package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;

class PinPolicyTest {

    private final PinPolicy policy = new PinPolicy();

    @ParameterizedTest
    @ValueSource(strings = { "284917", "905312", "471903", "638201" })
    void acceptsStrongPins(String pin) {
        assertThatCode(() -> policy.validate(pin)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "12345", "1234567", "abcdef", "12 456", "12.456" })
    void rejectsMalformedPins(String pin) {
        assertThatThrownBy(() -> policy.validate(pin)).isInstanceOf(InvalidPinException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "000000", "111111", "999999" })
    void rejectsRepeatedPins(String pin) {
        assertThatThrownBy(() -> policy.validate(pin)).isInstanceOf(InvalidPinException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "123456", "234567", "012345", "654321", "987654" })
    void rejectsSequentialPins(String pin) {
        assertThatThrownBy(() -> policy.validate(pin)).isInstanceOf(InvalidPinException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "123123", "121212", "112233", "159753", "696969" })
    void rejectsCommonPins(String pin) {
        assertThatThrownBy(() -> policy.validate(pin)).isInstanceOf(InvalidPinException.class);
    }

    @Test
    void rejectsNullPin() {
        assertThatThrownBy(() -> policy.validate(null)).isInstanceOf(InvalidPinException.class);
    }
}
