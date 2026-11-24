package me.sarahlacerda.gua.identityservice.account.genesis;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Ed25519KeysTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String IDENTITY = "0100000000000000000000000000000000000000000000000000000000000000";

    @ParameterizedTest
    @ValueSource(strings = {
            IDENTITY,
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"})
    void refusesSmallOrderKeys(String rawHex) {
        assertThatThrownBy(() -> Ed25519Keys.fromRaw(HEX.parseHex(rawHex), "invalid_key"))
                .isInstanceOf(InvalidGenesisException.class);
    }

    @Test
    void doesNotVerifyTheIdentityKeyForgery() {
        // Under the identity key, R = identity and S = 0 satisfy the cofactorless equation for every message.
        byte[] forged = HEX.parseHex(IDENTITY + "00".repeat(32));

        assertThat(Ed25519Keys.verify(HEX.parseHex(IDENTITY), "any message".getBytes(StandardCharsets.UTF_8),
                forged)).isFalse();
    }
}
