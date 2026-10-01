// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class AuthorityHeadRecordCodecTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final byte[] REFERENCE =
            HEX.parseHex("0100be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991");
    private static final byte[] HEAD_HASH =
            HEX.parseHex("98e09606da1f3021004badbccfb1f25eff5afb436787850651b92d118ce68510");
    private static final String HOMESERVER = "hs-alpha";
    private static final Instant ISSUED = Instant.parse("2026-09-24T00:00:00Z");
    private static final Instant NOT_AFTER = ISSUED.plus(Duration.ofDays(400));

    private static byte[] canonical() {
        return AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 7L, HOMESERVER, ISSUED, ISSUED, NOT_AFTER);
    }

    @Test
    void everyFieldSitsWhereTheLayoutSaysItDoes() {
        byte[] bytes = canonical();

        assertThat(bytes).hasSize(AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID + HOMESERVER.length());
        assertThat(new String(Arrays.copyOfRange(bytes, 0, 4), StandardCharsets.US_ASCII))
                .isEqualTo(AuthorityHeadRecord.MAGIC);
        assertThat(bytes[4] & 0xFF).isEqualTo(AuthorityHeadRecord.VERSION);
        assertThat(bytes[5] & 0xFF).isEqualTo(AuthorityRecord.SUITE_ED25519_SHA256);
        assertThat(Arrays.copyOfRange(bytes, 6, 40)).isEqualTo(REFERENCE);
        assertThat(Arrays.copyOfRange(bytes, 40, 72)).isEqualTo(HEAD_HASH);
        assertThat(Arrays.copyOfRange(bytes, 72, 80)).isEqualTo(new byte[] { 0, 0, 0, 0, 0, 0, 0, 7 });
        assertThat(bytes[80] & 0xFF).isEqualTo(HOMESERVER.length());
        assertThat(new String(Arrays.copyOfRange(bytes, 81, 89), StandardCharsets.US_ASCII))
                .isEqualTo(HOMESERVER);
    }

    @Test
    void theEnvelopeCarriesTheSameAccountReferenceLengthAChainRecordDoes() {
        assertThat(REFERENCE).hasSize(AuthorityRecord.ACCOUNT_REFERENCE_LENGTH);
        assertThat(AuthorityHeadRecordCodec.decode(canonical()).accountReference()).isEqualTo(REFERENCE);
    }

    @Test
    void theLayoutAccountsForEveryByteSoNoIdentifierCouldBeAddedWithoutBreakingIt() {
        int accounted = 4 + 1 + 1 + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + AuthorityRecord.HASH_LENGTH + 8 + 1;
        assertThat(accounted).isEqualTo(AuthorityHeadRecord.FIXED_PREFIX_LENGTH);
        assertThat(AuthorityHeadRecord.TRAILER_LENGTH).isEqualTo(3 * 8);
        assertThat(AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID)
                .isEqualTo(AuthorityHeadRecord.FIXED_PREFIX_LENGTH + AuthorityHeadRecord.TRAILER_LENGTH);
        assertThat(canonical()).hasSize(AuthorityHeadRecord.LENGTH_WITHOUT_HOMESERVER_ID + HOMESERVER.length());
    }

    @Test
    void noSourceLineOfTheHeadObjectNamesAnIdentifierField() throws Exception {
        List<String> offenders = Stream.of(
                        Path.of("src/main/java/me/sarahlacerda/gua/identityservice/account/authority",
                                "AuthorityHeadRecord.java"),
                        Path.of("src/main/java/me/sarahlacerda/gua/identityservice/account/authority",
                                "AuthorityHeadRecordCodec.java"))
                .flatMap(file -> {
                    try {
                        return Files.readAllLines(file).stream();
                    } catch (Exception ex) {
                        throw new IllegalStateException(ex);
                    }
                })
                .map(line -> line.replaceAll("\\s//.*$", "").trim())
                .filter(line -> !line.isEmpty() && !line.startsWith("//") && !line.startsWith("*")
                        && !line.startsWith("/*"))
                .filter(line -> line.matches(".*\\b(phone|phoneHash|userId|matrixId|localpart|deviceKey|label|"
                        + "msisdn|e164)\\b.*"))
                .toList();

        assertThat(offenders).isEmpty();
    }

    @Test
    void aRoundTripKeepsEveryFieldAndTheBytesAsReceived() {
        byte[] bytes = canonical();

        AuthorityHeadRecord decoded = AuthorityHeadRecordCodec.decode(bytes);

        assertThat(decoded.version()).isEqualTo(AuthorityHeadRecord.VERSION);
        assertThat(decoded.suite()).isEqualTo(AuthorityRecord.SUITE_ED25519_SHA256);
        assertThat(decoded.headHash()).isEqualTo(HEAD_HASH);
        assertThat(decoded.headHashHex()).isEqualTo(HEX.formatHex(HEAD_HASH));
        assertThat(decoded.headSeq()).isEqualTo(7L);
        assertThat(decoded.homeserverId()).isEqualTo(HOMESERVER);
        assertThat(decoded.issuedAt()).isEqualTo(ISSUED);
        assertThat(decoded.notBefore()).isEqualTo(ISSUED);
        assertThat(decoded.notAfter()).isEqualTo(NOT_AFTER);
        assertThat(decoded.canonicalBytes()).isEqualTo(bytes);
    }

    @Test
    void theLeafPayloadIsTheSha256OfTheCanonicalBytesAndNothingElse() throws Exception {
        byte[] bytes = canonical();

        String expected = HEX.formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));

        assertThat(AuthorityHeadRecordCodec.decode(bytes).payloadHashHex()).isEqualTo(expected);
    }

    @Test
    void theSignaturePreimageIsTheMagicThenTheCanonicalBytes() {
        byte[] bytes = canonical();

        byte[] preimage = AuthorityHeadRecordCodec.signaturePreimage(bytes);

        assertThat(preimage).hasSize(4 + bytes.length);
        assertThat(new String(Arrays.copyOfRange(preimage, 0, 4), StandardCharsets.US_ASCII))
                .isEqualTo(AuthorityHeadRecord.MAGIC);
        assertThat(Arrays.copyOfRange(preimage, 4, preimage.length)).isEqualTo(bytes);
    }

    @Test
    void theMagicIsNotOneAChainRecordUses() {
        assertThat(Stream.of(AuthorityRecordType.values()).map(AuthorityRecordType::magic))
                .doesNotContain(AuthorityHeadRecord.MAGIC);
    }

    @Test
    void anAllZeroHeadHashIsRefusedRatherThanEncoded() {
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, new byte[32], 1L, HOMESERVER,
                ISSUED, ISSUED, NOT_AFTER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty chain");

        byte[] bytes = canonical();
        Arrays.fill(bytes, 40, 72, (byte) 0);
        assertThat(reasonOf(bytes)).isEqualTo("empty_head_hash");
    }

    @Test
    void positionZeroIsRefusedRatherThanEncoded() {
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 0L, HOMESERVER, ISSUED,
                ISSUED, NOT_AFTER))
                .isInstanceOf(IllegalArgumentException.class);

        byte[] bytes = canonical();
        Arrays.fill(bytes, 72, 80, (byte) 0);
        assertThat(reasonOf(bytes)).isEqualTo("head_seq_out_of_range");
    }

    @Test
    void aPositionWithTheTopBitSetDoesNotWrapNegative() {
        byte[] bytes = canonical();
        bytes[72] = (byte) 0x80;

        assertThat(reasonOf(bytes)).isEqualTo("head_seq_out_of_range");
    }

    @Test
    void anUnknownMagicVersionOrSuiteIsRefused() {
        byte[] magic = canonical();
        magic[3] = 'Z';
        assertThat(reasonOf(magic)).isEqualTo("bad_magic");

        byte[] version = canonical();
        version[4] = 0x02;
        assertThat(reasonOf(version)).isEqualTo("unknown_version");

        byte[] suite = canonical();
        suite[5] = 0x02;
        assertThat(reasonOf(suite)).isEqualTo("unknown_suite");
    }

    @Test
    void aLengthPrefixThatDisagreesWithTheBufferIsRefused() {
        byte[] longer = canonical();
        longer[80] = (byte) (HOMESERVER.length() + 1);
        assertThat(reasonOf(longer)).isEqualTo("wrong_length");

        byte[] trailing = Arrays.copyOf(canonical(), canonical().length + 1);
        assertThat(reasonOf(trailing)).isEqualTo("wrong_length");

        byte[] truncated = Arrays.copyOf(canonical(), canonical().length - 1);
        assertThat(reasonOf(truncated)).isEqualTo("wrong_length");

        assertThat(reasonOf(new byte[10])).isEqualTo("wrong_length");
    }

    @Test
    void aHomeserverIdLengthOutOfRangeIsRefused() {
        byte[] empty = canonical();
        empty[80] = 0;
        assertThat(reasonOf(empty)).isEqualTo("bad_homeserver_id_length");

        byte[] tooLong = canonical();
        tooLong[80] = (byte) (AuthorityHeadRecord.MAX_HOMESERVER_ID_LENGTH + 1);
        assertThat(reasonOf(tooLong)).isEqualTo("bad_homeserver_id_length");

        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 1L, "", ISSUED, ISSUED,
                NOT_AFTER)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 1L, "x".repeat(65),
                ISSUED, ISSUED, NOT_AFTER)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aHomeserverIdOutsidePrintableAsciiIsRefusedInBothDirections() {
        byte[] bytes = canonical();
        bytes[81] = 0x0a;
        assertThat(reasonOf(bytes)).isEqualTo("bad_homeserver_id");

        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 1L, "hs alpha", ISSUED,
                ISSUED, NOT_AFTER))
                .isInstanceOf(InvalidAuthorityRecordException.class);
    }

    @Test
    void anInvertedOrOverLongWindowIsRefused() {
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 1L, HOMESERVER, ISSUED,
                ISSUED, ISSUED)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, HEAD_HASH, 1L, HOMESERVER, ISSUED,
                ISSUED, ISSUED.plus(Duration.ofDays(401)))).isInstanceOf(IllegalArgumentException.class);

        byte[] inverted = canonical();
        int trailer = 81 + HOMESERVER.length();
        System.arraycopy(inverted, trailer + 8, inverted, trailer + 16, 8);
        assertThat(reasonOf(inverted)).isEqualTo("inverted_window");

        byte[] tooLong = canonical();
        long past = ISSUED.plus(Duration.ofDays(401)).toEpochMilli();
        for (int i = 0; i < 8; i++) {
            tooLong[trailer + 16 + i] = (byte) (past >>> (56 - 8 * i));
        }
        assertThat(reasonOf(tooLong)).isEqualTo("window_too_long");
    }

    @Test
    void theWindowCapIsTheOneAPlacementRecordSignedByTheSameKeyObeys() {
        assertThat(AuthorityHeadRecordCodec.MAX_VALIDITY)
                .isEqualTo(me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec.MAX_VALIDITY);
    }

    @Test
    void aWrongLengthReferenceOrHeadHashIsRefusedAtSigningTime() {
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(new byte[33], HEAD_HASH, 1L, HOMESERVER,
                ISSUED, ISSUED, NOT_AFTER)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuthorityHeadRecordCodec.encode(REFERENCE, new byte[31], 1L, HOMESERVER,
                ISSUED, ISSUED, NOT_AFTER)).isInstanceOf(IllegalArgumentException.class);
    }

    private static String reasonOf(byte[] bytes) {
        InvalidAuthorityRecordException thrown = catchThrowableOfType(
                () -> AuthorityHeadRecordCodec.decode(bytes), InvalidAuthorityRecordException.class);
        assertThat(thrown).as("these bytes must be refused").isNotNull();
        return thrown.reason();
    }
}
