package me.sarahlacerda.gua.identityservice.account.genesis;

import java.util.Arrays;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Every rule ADM-008 decision 1 states for {@code AccountGenesis}, suite 0x01, and the rule that the
 * accountId covers the bytes as received.
 */
class AccountGenesisCodecTest {

    private static final HexFormat HEX = HexFormat.of();

    private final TestEd25519.Pair authority = TestEd25519.generate();
    private final TestEd25519.Pair recovery = TestEd25519.generate();

    private byte[] valid() {
        return AccountGenesisCodec.encode(authority.rawPublicKey(),
                AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY, recovery.rawPublicKey(), entropy());
    }

    private static byte[] entropy() {
        return HEX.parseHex("000102030405060708090a0b0c0d0e0f");
    }

    private static void refusedWith(byte[] bytes, String reason) {
        assertThatThrownBy(() -> AccountGenesisCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo(reason);
    }

    @Test
    void theCanonicalLayoutIs87BytesInTheDocumentedOrder() {
        byte[] bytes = valid();

        assertThat(bytes).hasSize(87);
        assertThat(new String(Arrays.copyOfRange(bytes, 0, 4))).isEqualTo("GUAG");
        assertThat(bytes[4]).isEqualTo((byte) 0x01);
        assertThat(bytes[5]).isEqualTo((byte) 0x01);
        assertThat(Arrays.copyOfRange(bytes, 6, 38)).isEqualTo(authority.rawPublicKey());
        assertThat(bytes[38]).isEqualTo((byte) 0x01);
        assertThat(Arrays.copyOfRange(bytes, 39, 71)).isEqualTo(recovery.rawPublicKey());
        assertThat(Arrays.copyOfRange(bytes, 71, 87)).isEqualTo(entropy());
    }

    @Test
    void decodeReadsEveryFieldBack() {
        AccountGenesis genesis = AccountGenesisCodec.decode(valid());

        assertThat(genesis.genesisVersion()).isEqualTo(0x01);
        assertThat(genesis.suite()).isEqualTo(0x01);
        assertThat(genesis.recoveryFrameworkId()).isEqualTo(0x01);
        assertThat(genesis.authorityPublicKey()).isEqualTo(authority.rawPublicKey());
        assertThat(genesis.recoveryAuthorityPublicKey()).isEqualTo(recovery.rawPublicKey());
        assertThat(genesis.entropy()).isEqualTo(entropy());
        assertThat(genesis.canonicalBytes()).isEqualTo(valid());
    }

    @Test
    void theAccountIdCoversTheBytesAsReceived() {
        byte[] bytes = valid();
        AccountGenesis genesis = AccountGenesisCodec.decode(bytes);

        assertThat(genesis.accountId().value())
                .isEqualTo(AccountId.derive(AccountId.CLASS_GENESIS, bytes).value());
        assertThat(genesis.accountId().isGenesisRooted()).isTrue();
    }

    @Test
    void theDecodedObjectCannotBeMutatedThroughItsAccessors() {
        AccountGenesis genesis = AccountGenesisCodec.decode(valid());

        byte[] borrowed = genesis.canonicalBytes();
        Arrays.fill(borrowed, (byte) 0);

        assertThat(genesis.canonicalBytes()).isEqualTo(valid());
        assertThat(genesis.accountId().value())
                .isEqualTo(AccountId.derive(AccountId.CLASS_GENESIS, valid()).value());
    }

    @Test
    void anyOtherLengthIsRejected() {
        refusedWith(Arrays.copyOf(valid(), 86), "wrong_length");
        refusedWith(Arrays.copyOf(valid(), 88), "wrong_length");
        refusedWith(new byte[0], "wrong_length");
        refusedWith(null, "wrong_length");
    }

    @Test
    void anotherMagicIsRejected() {
        byte[] bytes = valid();
        bytes[3] = 'X';
        refusedWith(bytes, "bad_magic");
    }

    @Test
    void anUnknownVersionSuiteOrFrameworkIsRejected() {
        byte[] version = valid();
        version[4] = 0x02;
        refusedWith(version, "unknown_version");

        byte[] suite = valid();
        suite[5] = 0x02;
        refusedWith(suite, "unknown_suite");

        byte[] framework = valid();
        framework[38] = 0x02;
        refusedWith(framework, "unknown_recovery_framework");
    }

    @Test
    void anAllZeroKeyIsRejectedEvenThoughItDecodesToAPoint() {
        // The all-zero encoding is a valid low-order point, which is why ADM-008 states the rule
        // separately from point decoding.
        assertThat(Ed25519Keys.isOnCurve(new byte[32])).isTrue();

        byte[] zeroAuthority = valid();
        Arrays.fill(zeroAuthority, 6, 38, (byte) 0);
        refusedWith(zeroAuthority, "zero_authority_key");

        byte[] zeroRecovery = valid();
        Arrays.fill(zeroRecovery, 39, 71, (byte) 0);
        refusedWith(zeroRecovery, "zero_recovery_key");
    }

    @Test
    void aRecoveryKeyEqualToTheAuthorityKeyIsRejected() {
        byte[] bytes = valid();
        System.arraycopy(authority.rawPublicKey(), 0, bytes, 39, 32);
        refusedWith(bytes, "duplicate_keys");
    }

    @Test
    void aKeyThatIsNotACurvePointIsRejected() {
        byte[] badAuthority = valid();
        Arrays.fill(badAuthority, 6, 38, (byte) 0xFF);
        refusedWith(badAuthority, "invalid_authority_key");

        byte[] badRecovery = valid();
        Arrays.fill(badRecovery, 39, 71, (byte) 0xFF);
        refusedWith(badRecovery, "invalid_recovery_key");
    }

    @Test
    void encodeRefusesAWrongSizedKeyOrEntropy() {
        assertThatThrownBy(() -> AccountGenesisCodec.encode(new byte[31], 1, recovery.rawPublicKey(), entropy()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AccountGenesisCodec.encode(authority.rawPublicKey(), 1, new byte[33], entropy()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AccountGenesisCodec.encode(authority.rawPublicKey(), 1, recovery.rawPublicKey(),
                new byte[15])).isInstanceOf(IllegalArgumentException.class);
    }
}
