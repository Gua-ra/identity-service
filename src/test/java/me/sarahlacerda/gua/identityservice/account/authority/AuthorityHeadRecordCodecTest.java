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

/**
 * The bytes of {@code gua-account-authority-head.v1}, which is what the {@code ACCOUNT_AUTHORITY} leaf of
 * ADM-009 decision 12 commits the SHA-256 of.
 *
 * <p>Three claims are checked here, and each one is load-bearing for something outside this class.
 *
 * <ul>
 *   <li><b>One canonical spelling.</b> Every field sits at a fixed offset, the one variable field carries a
 *       length prefix the buffer has to agree with exactly, and a decoder refuses anything else with a named
 *       reason. Without that, one head has several spellings, and a signature over the longer buffer would
 *       still verify while the payload hash the leaf committed covered different bytes.</li>
 *   <li><b>No identifier, and no room for one.</b> The log gets a hash of these bytes, and the bytes
 *       themselves travel beside it, so anything in this layout is effectively published. There is no phone,
 *       no phone hash, no Matrix user id, no device key and no label, and the length arithmetic below leaves
 *       no unaccounted byte a field like that could be added in without this test failing.</li>
 *   <li><b>An empty chain is not publishable.</b> The all-zero head hash and position zero are what the head
 *       row holds while a chain has no record, and an object saying so would be a non-membership claim with
 *       nothing anywhere in this system to check it against.</li>
 * </ul>
 */
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

    // --- The layout -----------------------------------------------------------

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
        // The 34 bytes are the whole of what a head says about which account it is, and they are exactly the
        // bytes the chain envelope carries, so a client signs and publishes over one value and not two.
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
        // A guard on the layout itself rather than on the arithmetic: a new field named for a phone, a user
        // id, a device or a label would be the one way this object stopped being publishable, so the two
        // files that define it may not mention one at all.
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

    // --- The round trip -------------------------------------------------------

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

        // This is the whole of what the ACCOUNT_AUTHORITY leaf commits. A verifier handed the envelope
        // recomputes it from the bytes it was handed and reaches the leaf from there; nothing in the log
        // holds any field of this object.
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
        // The magic is the signature domain, so a head signature must not be readable as a chain record's.
        assertThat(Stream.of(AuthorityRecordType.values()).map(AuthorityRecordType::magic))
                .doesNotContain(AuthorityHeadRecord.MAGIC);
    }

    // --- What a decoder refuses ----------------------------------------------

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

        // One trailing byte. Accepting it would give this head two spellings, and a signature over the
        // longer buffer would verify while the leaf's payload hash covered the shorter one.
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

        // Refused at signing time too, so an id this service could not read back never leaves it.
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
        // Both are a homeserver's standing assertion about one account under its roster membership key. A head
        // outliving the placement record for the same account would be the longer-lived claim of the two.
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
