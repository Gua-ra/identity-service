package me.sarahlacerda.gua.identityservice.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class MatrixIdsTest {

    @Test
    void returnsTheLocalpartOfAMatrixUserId() {
        assertThat(MatrixIds.isMatrixUserId("@alice:dev.local")).isTrue();
        assertThat(MatrixIds.localpartOf("@alice:dev.local")).isEqualTo("alice");
        assertThat(MatrixIds.localpartOf("@alice.b_c-d:dev.local:8448")).isEqualTo("alice.b_c-d");
    }

    /**
     * The old helper returned the text before the first colon of any string, so
     * {@code ga1abc:x} and {@code ga1abc:y} both became {@code ga1abc}. Anything that is not
     * {@code @localpart:server} is refused instead.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "ga1abc:x", "ga1abc:y", "u1", "alice", "alice:dev.local", "@alice", "@:dev.local",
            "@alice:", " @alice:dev.local" })
    void refusesAnythingThatIsNotAMatrixUserId(String value) {
        assertThat(MatrixIds.isMatrixUserId(value)).isFalse();
        assertThatThrownBy(() -> MatrixIds.localpartOf(value)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusalNeverEchoesTheValue() {
        assertThatThrownBy(() -> MatrixIds.localpartOf("ga1secretvalue:x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("ga1secretvalue");
    }
}
