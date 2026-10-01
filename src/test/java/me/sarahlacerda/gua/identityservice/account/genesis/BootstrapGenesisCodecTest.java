package me.sarahlacerda.gua.identityservice.account.genesis;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BootstrapGenesisCodecTest {

    private static byte[] valid() {
        return BootstrapGenesisCodec.encode(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
    }

    private static void refusedWith(byte[] bytes, String reason) {
        assertThatThrownBy(() -> BootstrapGenesisCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting(e -> ((InvalidGenesisException) e).reason())
                .isEqualTo(reason);
    }

    @Test
    void theCanonicalLayoutIs22BytesInTheDocumentedOrder() {
        byte[] bytes = valid();

        assertThat(bytes).hasSize(22);
        assertThat(new String(Arrays.copyOfRange(bytes, 0, 4))).isEqualTo("GUAB");
        assertThat(bytes[4]).isEqualTo((byte) 0x01);
        assertThat(bytes[5]).isEqualTo((byte) 0x00);
    }

    @Test
    void theAccountIdCarriesTheBootstrapRootClass() {
        BootstrapGenesis genesis = BootstrapGenesisCodec.decode(valid());

        assertThat(genesis.accountId().rootClass()).isEqualTo(AccountId.CLASS_BOOTSTRAP);
        assertThat(genesis.accountId().isGenesisRooted()).isFalse();
        assertThat(genesis.canonicalBytes()).isEqualTo(valid());
    }

    @Test
    void mintDrawsFreshEntropyEveryTime() {
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
            assertThat(genesis.entropy()).hasSize(16);
            ids.add(genesis.accountId().value());
        }

        assertThat(ids).hasSize(50);
    }

    @Test
    void anyOtherLengthMagicVersionOrSuiteIsRejected() {
        refusedWith(Arrays.copyOf(valid(), 21), "wrong_length");
        refusedWith(null, "wrong_length");

        byte[] magic = valid();
        magic[3] = 'X';
        refusedWith(magic, "bad_magic");

        byte[] version = valid();
        version[4] = 0x02;
        refusedWith(version, "unknown_version");

        // 0x01 is the AccountGenesis suite.
        byte[] suite = valid();
        suite[5] = 0x01;
        refusedWith(suite, "unknown_suite");
    }

    @Test
    void aBootstrapObjectIsNeverConfusableWithAGenesisOne() {
        assertThatThrownBy(() -> AccountGenesisCodec.decode(valid()))
                .isInstanceOf(InvalidGenesisException.class);
    }
}
