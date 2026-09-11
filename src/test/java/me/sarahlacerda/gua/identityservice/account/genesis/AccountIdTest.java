package me.sarahlacerda.gua.identityservice.account.genesis;

import java.util.HexFormat;
import java.util.Locale;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * ADM-008 decision 2: an accountId is {@code "ga1" || base32(0x01 || class || SHA-256(bytes))} and has
 * exactly one canonical spelling.
 */
class AccountIdTest {

    private static final HexFormat HEX = HexFormat.of();

    private static AccountId genesisRooted() {
        return AccountId.derive(AccountId.CLASS_GENESIS, "some canonical bytes".getBytes());
    }

    @Test
    void anAccountIdIs58CharactersAndCarries34Bytes() {
        AccountId id = genesisRooted();

        assertThat(id.value()).hasSize(58).startsWith("ga1");
        assertThat(id.rawBytes()).hasSize(34);
        assertThat(id.value()).matches(AccountId.CANONICAL_PATTERN);
    }

    @Test
    void thePrefixBytesAreTheFormatVersionAndTheRootClass() {
        AccountId genesis = AccountId.derive(AccountId.CLASS_GENESIS, new byte[] { 1 });
        AccountId bootstrap = AccountId.derive(AccountId.CLASS_BOOTSTRAP, new byte[] { 1 });

        assertThat(genesis.rawBytes()[0]).isEqualTo(AccountId.FORMAT_VERSION);
        assertThat(genesis.rawBytes()[1]).isEqualTo(AccountId.CLASS_GENESIS);
        assertThat(genesis.isGenesisRooted()).isTrue();
        assertThat(bootstrap.rawBytes()[1]).isEqualTo(AccountId.CLASS_BOOTSTRAP);
        assertThat(bootstrap.isGenesisRooted()).isFalse();
        // Same bytes, different class: a bootstrap id is never confusable with a rooted one.
        assertThat(genesis.value()).isNotEqualTo(bootstrap.value());
    }

    @Test
    void theDigestIsSha256OfTheBytesAsGiven() throws Exception {
        byte[] bytes = "hash exactly this".getBytes();
        AccountId id = AccountId.derive(AccountId.CLASS_GENESIS, bytes);

        assertThat(id.digestHex()).isEqualTo(HEX.formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(bytes)));
    }

    @Test
    void onlyAIQAndYCanEndAWellFormedId() {
        // The last character carries three unused bits, so exactly four of the 32 are reachable.
        for (int i = 0; i < 200; i++) {
            AccountId id = AccountId.derive(AccountId.CLASS_GENESIS, ("entropy " + i).getBytes());
            assertThat(id.value().charAt(57)).isIn('a', 'i', 'q', 'y');
        }
    }

    @Test
    void parseRoundTripsTheCanonicalSpelling() {
        AccountId id = genesisRooted();

        AccountId parsed = AccountId.parse(id.value());

        assertThat(parsed.value()).isEqualTo(id.value());
        assertThat(parsed.rawBytes()).isEqualTo(id.rawBytes());
        assertThat(parsed).isEqualTo(id);
    }

    @Test
    void parseRefusesAnUppercaseSpelling() {
        String upper = genesisRooted().value().toUpperCase(Locale.ROOT);

        assertThatThrownBy(() -> AccountId.parse(upper))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo("bad_account_id");
    }

    @Test
    void parseRefusesTheSevenNonCanonicalFinalCharacters() {
        String head = genesisRooted().value().substring(0, 57);

        for (char c : "bcdefgh".toCharArray()) {
            String spelling = head + c;
            assertThatThrownBy(() -> AccountId.parse(spelling))
                    .as("final character " + c)
                    .isInstanceOf(InvalidGenesisException.class);
        }
    }

    @Test
    void parseRefusesAWrongPrefixLengthOrAlphabet() {
        String good = genesisRooted().value();

        assertThatThrownBy(() -> AccountId.parse("gax" + good.substring(3)))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> AccountId.parse(good.substring(0, good.length() - 1)))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> AccountId.parse(good + "a"))
                .isInstanceOf(InvalidGenesisException.class);
        // 0, 1 and 8 are outside the RFC 4648 base32 alphabet.
        assertThatThrownBy(() -> AccountId.parse(good.substring(0, 56) + "1" + good.charAt(57)))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> AccountId.parse(null))
                .isInstanceOf(InvalidGenesisException.class);
    }

    @Test
    void parseRefusesAnUnknownFormatVersionOrRootClass() {
        byte[] raw = genesisRooted().rawBytes();

        byte[] badVersion = raw.clone();
        badVersion[0] = 0x02;
        assertThatThrownBy(() -> AccountId.parse("ga1" + Base32.encode(badVersion)))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo("unknown_account_id_version");

        byte[] badClass = raw.clone();
        badClass[1] = 0x02;
        assertThatThrownBy(() -> AccountId.parse("ga1" + Base32.encode(badClass)))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo("unknown_root_class");
    }

    @Test
    void deriveRefusesAnUnknownRootClass() {
        assertThatThrownBy(() -> AccountId.derive((byte) 0x02, new byte[] { 1 }))
                .isInstanceOf(InvalidGenesisException.class);
    }

    @Test
    void distinctBytesGiveDistinctIds() {
        assertThat(AccountId.derive(AccountId.CLASS_GENESIS, new byte[] { 1 }).value())
                .isNotEqualTo(AccountId.derive(AccountId.CLASS_GENESIS, new byte[] { 2 }).value());
    }
}
