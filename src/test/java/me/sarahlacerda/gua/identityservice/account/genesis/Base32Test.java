package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** RFC 4648 base32, lowercase and unpadded, with a decoder that admits exactly one spelling per value. */
class Base32Test {

    /** RFC 4648 section 10 test vectors, lowercased and stripped of padding. */
    @Test
    void theRfc4648TestVectorsReproduce() {
        assertThat(encode("")).isEmpty();
        assertThat(encode("f")).isEqualTo("my");
        assertThat(encode("fo")).isEqualTo("mzxq");
        assertThat(encode("foo")).isEqualTo("mzxw6");
        assertThat(encode("foob")).isEqualTo("mzxw6yq");
        assertThat(encode("fooba")).isEqualTo("mzxw6ytb");
        assertThat(encode("foobar")).isEqualTo("mzxw6ytboi");
    }

    @Test
    void decodeIsTheInverseOfEncode() {
        for (String value : new String[] { "", "f", "fo", "foo", "foob", "fooba", "foobar" }) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            assertThat(Base32.decode(Base32.encode(bytes))).isEqualTo(bytes);
        }
    }

    @Test
    void decodeRefusesCharactersOutsideTheLowercaseAlphabet() {
        assertThatThrownBy(() -> Base32.decode("MZXW6"))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> Base32.decode("mzxw0"))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> Base32.decode("mzxw6==="))
                .isInstanceOf(InvalidGenesisException.class);
    }

    @Test
    void decodeRefusesALengthNoEncodingProduces() {
        for (String value : new String[] { "m", "mzx", "mzxw6y" }) {
            assertThatThrownBy(() -> Base32.decode(value))
                    .as(value)
                    .isInstanceOf(InvalidGenesisException.class);
        }
    }

    @Test
    void decodeRefusesNonZeroTrailingBits() {
        // "mzxw6" decodes "foo" with three spare bits; "mzxw7" sets one of them, so it is a second
        // spelling of the same three bytes and must be refused.
        assertThat(Base32.decode("mzxw6")).isEqualTo("foo".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> Base32.decode("mzxw7"))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo("bad_base32");
    }

    private static String encode(String value) {
        return Base32.encode(value.getBytes(StandardCharsets.UTF_8));
    }
}
