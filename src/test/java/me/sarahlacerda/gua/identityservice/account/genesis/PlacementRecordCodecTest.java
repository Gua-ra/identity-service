// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.genesis;

import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The generation-1 placement record wire format (ADM-008 encoding tables, decision 7). */
class PlacementRecordCodecTest {

    private static final String HOMESERVER = "fed-primary";

    private final Instant now = Instant.parse("2026-09-11T00:00:00Z");

    private AccountId genesisRootedId() {
        return AccountId.derive(AccountId.CLASS_GENESIS, "one account".getBytes(StandardCharsets.UTF_8));
    }

    private AccountId bootstrapId() {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, "another account".getBytes(StandardCharsets.UTF_8));
    }

    private byte[] valid() {
        AccountId accountId = genesisRootedId();
        return PlacementRecordCodec.encode(accountId, AccountId.CLASS_GENESIS, HOMESERVER, now, now,
                now.plus(400, ChronoUnit.DAYS));
    }

    // --- The layout ----------------------------------------------------------

    @Test
    void aRecordRoundTripsAndKeepsTheBytesItWasGiven() {
        AccountId accountId = genesisRootedId();
        Instant notAfter = now.plus(400, ChronoUnit.DAYS);
        byte[] bytes = PlacementRecordCodec.encode(accountId, AccountId.CLASS_GENESIS, HOMESERVER, now, now,
                notAfter);

        PlacementRecord decoded = PlacementRecordCodec.decode(bytes);

        assertThat(decoded.version()).isEqualTo(PlacementRecord.VERSION);
        assertThat(decoded.generation()).isEqualTo(PlacementRecord.GENERATION_ONE);
        assertThat(decoded.accountId()).isEqualTo(accountId);
        assertThat(decoded.origin()).isEqualTo(AccountId.CLASS_GENESIS);
        assertThat(decoded.homeserverId()).isEqualTo(HOMESERVER);
        assertThat(decoded.issuedAt()).isEqualTo(now);
        assertThat(decoded.notBefore()).isEqualTo(now);
        assertThat(decoded.notAfter()).isEqualTo(notAfter);
        // The signature covers what arrived, so the decoded object must hand back exactly that.
        assertThat(decoded.canonicalBytes()).isEqualTo(bytes);
    }

    @Test
    void theLengthIsSixtySixPlusTheHomeserverId() {
        assertThat(valid()).hasSize(PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + HOMESERVER.length());
        assertThat(PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID).isEqualTo(66);
    }

    @Test
    void theMagicIsTheFirstFourBytesAndTheSignatureDomain() {
        assertThat(Arrays.copyOfRange(valid(), 0, 4)).isEqualTo("GUAP".getBytes(StandardCharsets.US_ASCII));
        assertThat(PlacementRecord.MAGIC).isEqualTo("GUAP");
    }

    @Test
    void theOriginByteSitsBesideTheAccountIdItMustAgreeWith() {
        byte[] bytes = valid();
        // accountId raw starts at 6, so its class byte is at absolute offset 7, and the origin is at 40.
        assertThat(bytes[7]).isEqualTo(AccountId.CLASS_GENESIS);
        assertThat(bytes[40]).isEqualTo(AccountId.CLASS_GENESIS);
    }

    // --- The rejection rules -------------------------------------------------

    @Test
    void aShortBufferIsRefused() {
        assertThatThrownBy(() -> PlacementRecordCodec.decode(new byte[10]))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("wrong_length");
    }

    @Test
    void aWrongMagicIsRefused() {
        byte[] bytes = valid();
        bytes[0] = 'X';
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("bad_magic");
    }

    @Test
    void anUnknownVersionIsRefused() {
        byte[] bytes = valid();
        bytes[4] = 0x02;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("unknown_version");
    }

    @Test
    void anUnknownGenerationIsRefused() {
        byte[] bytes = valid();
        bytes[5] = 0x02;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("unknown_generation");
    }

    @Test
    void anOriginByteThatDisagreesWithTheAccountIdClassIsRefused() {
        byte[] bytes = valid();
        bytes[40] = AccountId.CLASS_BOOTSTRAP;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("origin_class_mismatch");
        // And the encoder refuses to build one in the first place.
        assertThatThrownBy(() -> PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_BOOTSTRAP,
                HOMESERVER, now, now, now.plus(1, ChronoUnit.DAYS)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aBootstrapAccountCarriesTheBootstrapOrigin() {
        AccountId bootstrap = bootstrapId();
        PlacementRecord decoded = PlacementRecordCodec.decode(PlacementRecordCodec.encode(bootstrap,
                AccountId.CLASS_BOOTSTRAP, HOMESERVER, now, now, now.plus(10, ChronoUnit.DAYS)));

        assertThat(decoded.origin()).isEqualTo(AccountId.CLASS_BOOTSTRAP);
        assertThat(decoded.isGenesisRooted()).isFalse();
    }

    @Test
    void aLengthPrefixThatDisagreesWithTheBufferIsRefused() {
        byte[] bytes = valid();
        bytes[41] = (byte) (HOMESERVER.length() + 1);
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("wrong_length");
    }

    @Test
    void aTrailingByteIsRefused() {
        byte[] bytes = valid();
        byte[] longer = Arrays.copyOf(bytes, bytes.length + 1);
        // Otherwise one record would have several spellings and a signature over the longer buffer would
        // still verify.
        assertThatThrownBy(() -> PlacementRecordCodec.decode(longer))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("wrong_length");
    }

    @Test
    void anEmptyOrOverLongHomeserverIdIsRefusedByTheEncoder() {
        assertThatThrownBy(() -> PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_GENESIS, "",
                now, now, now.plus(1, ChronoUnit.DAYS))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_GENESIS,
                "a".repeat(65), now, now, now.plus(1, ChronoUnit.DAYS)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aHomeserverIdWithAControlCharacterIsRefused() {
        byte[] bytes = valid();
        bytes[42] = 0x0A;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("bad_homeserver_id");
    }

    @Test
    void anInvertedWindowIsRefusedByTheEncoder() {
        assertThatThrownBy(() -> PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_GENESIS,
                HOMESERVER, now, now.plus(5, ChronoUnit.DAYS), now))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aWindowLongerThanFourHundredDaysIsRefusedByTheEncoder() {
        assertThat(PlacementRecordCodec.MAX_VALIDITY).isEqualTo(Duration.ofDays(400));
        assertThatThrownBy(() -> PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_GENESIS,
                HOMESERVER, now, now, now.plus(401, ChronoUnit.DAYS)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aTimestampWithTheTopBitSetIsRefused() {
        byte[] bytes = valid();
        int trailer = 42 + HOMESERVER.length();
        bytes[trailer] = (byte) 0x80;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("timestamp_out_of_range");
    }

    @Test
    void anAccountIdWithAnUnknownFormatVersionIsRefused() {
        byte[] bytes = valid();
        bytes[6] = 0x02;
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("unknown_account_id_version");
    }

    // --- The decoder rules the encoder cannot reach --------------------------
    //
    // The encoder is the trusted side: this service builds those bytes itself. The decoder is the side
    // that sees whatever arrives, and ResolverPlacementClient.findRecord runs it over bytes fetched from
    // the resolver, swallowing the failure and logging only the reason. A missing or wrong reason there
    // is invisible, so each rule below is pinned by its exact token. The buffers are assembled by hand
    // because the encoder refuses to produce them, which is why encode-based tests could never have
    // covered these branches.

    @Test
    void aZeroLengthHomeserverIdPrefixIsRefusedByTheDecoder() {
        byte[] bytes = handBuilt(0, HOMESERVER, now.toEpochMilli(), now.toEpochMilli(),
                now.plus(1, ChronoUnit.DAYS).toEpochMilli());

        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("bad_homeserver_id_length");
    }

    @Test
    void aHomeserverIdPrefixOverSixtyFourIsRefusedByTheDecoder() {
        String overLong = "a".repeat(PlacementRecord.MAX_HOMESERVER_ID_LENGTH + 1);
        byte[] bytes = handBuilt(overLong.length(), overLong, now.toEpochMilli(), now.toEpochMilli(),
                now.plus(1, ChronoUnit.DAYS).toEpochMilli());

        // Sized to match its own prefix, so only the range check can refuse it and a wrong_length here
        // would mean the range check had been removed.
        assertThat(bytes).hasSize(PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + overLong.length());
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("bad_homeserver_id_length");
    }

    @Test
    void aWindowThatEndsBeforeItStartsIsRefusedByTheDecoder() {
        long start = now.toEpochMilli();
        byte[] bytes = handBuilt(HOMESERVER.length(), HOMESERVER, start,
                now.plus(5, ChronoUnit.DAYS).toEpochMilli(), start);

        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("inverted_window");
    }

    @Test
    void aWindowOfNoDurationIsRefusedByTheDecoder() {
        long instant = now.toEpochMilli();
        byte[] bytes = handBuilt(HOMESERVER.length(), HOMESERVER, instant, instant, instant);

        // notAfter must be strictly after notBefore, so a zero-length window is refused too.
        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("inverted_window");
    }

    @Test
    void aWindowLongerThanFourHundredDaysIsRefusedByTheDecoder() {
        long start = now.toEpochMilli();
        byte[] bytes = handBuilt(HOMESERVER.length(), HOMESERVER, start, start,
                now.plus(401, ChronoUnit.DAYS).toEpochMilli());

        assertThatThrownBy(() -> PlacementRecordCodec.decode(bytes))
                .isInstanceOf(InvalidGenesisException.class)
                .extracting("reason").isEqualTo("window_too_long");
    }

    @Test
    void aWindowOfExactlyFourHundredDaysIsAccepted() {
        long start = now.toEpochMilli();
        byte[] bytes = handBuilt(HOMESERVER.length(), HOMESERVER, start, start,
                now.plus(400, ChronoUnit.DAYS).toEpochMilli());

        // The boundary is inclusive, so the tests above fail for the rule they name and not for an
        // off-by-one in the hand-built buffer.
        assertThat(PlacementRecordCodec.decode(bytes).homeserverId()).isEqualTo(HOMESERVER);
    }

    /**
     * Canonical bytes assembled directly, so the decoder can be handed a buffer the encoder would refuse
     * to build. Everything except the length prefix and the three timestamps is well formed, so each
     * test above fails for exactly the rule it names.
     */
    private byte[] handBuilt(int lengthPrefix, String homeserverId, long issuedAt, long notBefore,
            long notAfter) {
        byte[] idBytes = homeserverId.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[PlacementRecord.LENGTH_WITHOUT_HOMESERVER_ID + idBytes.length];
        System.arraycopy(PlacementRecord.MAGIC.getBytes(StandardCharsets.US_ASCII), 0, out, 0, 4);
        out[4] = (byte) PlacementRecord.VERSION;
        out[5] = (byte) PlacementRecord.GENERATION_ONE;
        System.arraycopy(genesisRootedId().rawBytes(), 0, out, 6, AccountId.RAW_LENGTH);
        out[40] = AccountId.CLASS_GENESIS;
        out[41] = (byte) lengthPrefix;
        System.arraycopy(idBytes, 0, out, 42, idBytes.length);
        int trailer = 42 + idBytes.length;
        writeUnsignedLong(out, trailer, issuedAt);
        writeUnsignedLong(out, trailer + 8, notBefore);
        writeUnsignedLong(out, trailer + 16, notAfter);
        return out;
    }

    private static void writeUnsignedLong(byte[] out, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >>> (56 - 8 * i));
        }
    }

    // --- ADM-001 L15: nothing in a record identifies the human ---------------

    @Test
    void aRecordCarriesNoIdentifierNoPhoneNoPhoneHashAndNoMatrixUserId() {
        String userId = "@alice:example.test";
        String phone = "+15550001111";
        String phoneHash = HexFormat.of().formatHex(sha256(phone));

        byte[] bytes = PlacementRecordCodec.encode(genesisRootedId(), AccountId.CLASS_GENESIS, HOMESERVER,
                now, now, now.plus(400, ChronoUnit.DAYS));
        String asText = new String(bytes, StandardCharsets.ISO_8859_1);

        assertThat(asText).doesNotContain(userId);
        assertThat(asText).doesNotContain("alice");
        assertThat(asText).doesNotContain("example.test");
        assertThat(asText).doesNotContain(phone);
        assertThat(asText).doesNotContain(phoneHash);
        assertThat(indexOf(bytes, sha256(phone))).isEqualTo(-1);
    }

    /**
     * The structural half of the same rule. A field added to this record is a field that would travel in
     * replicated federation state, so the list is pinned: growing it has to be a deliberate edit here,
     * with ADM-001 L15 in front of whoever makes it.
     */
    @Test
    void theRecordTypeHasExactlyTheFieldsAdm008Lists() {
        List<String> components = Arrays.stream(PlacementRecord.class.getRecordComponents())
                .map(RecordComponent::getName)
                .toList();

        assertThat(components).containsExactly("version", "generation", "accountId", "origin", "homeserverId",
                "issuedAt", "notBefore", "notAfter", "canonicalBytes");
        assertThat(components).noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).contains("phone"));
        assertThat(components).noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).contains("user"));
        assertThat(components).noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).contains("mxid"));
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
