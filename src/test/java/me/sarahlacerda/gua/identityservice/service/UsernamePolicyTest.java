package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import me.sarahlacerda.gua.identityservice.exception.InvalidUsernameException;

class UsernamePolicyTest {

    private final UsernamePolicy policy = new UsernamePolicy();

    @ParameterizedTest
    @ValueSource(strings = {"support", "sup.port", "a-d-m-i-n", "g_u_a", "Staff.", " Matrix_ "})
    void refusesReservedNamesWithOrWithoutSeparators(String requested) {
        assertThatThrownBy(() -> policy.normalizeAndValidate(requested))
                .isInstanceOf(InvalidUsernameException.class)
                .hasMessage("That username is reserved");
    }

    @ParameterizedTest
    @ValueSource(strings = {"joao.silva", "support1", "admins", "gua.fan"})
    void acceptsNamesThatOnlyContainAReservedWord(String requested) {
        assertThat(policy.normalizeAndValidate(requested)).isEqualTo(requested);
    }

    @Test
    void existingAccountsAreCheckedForFormatOnly() {
        assertThat(UsernamePolicy.hasValidFormat("sup.port")).isTrue();
    }
}
