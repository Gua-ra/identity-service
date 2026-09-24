// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The published golden vectors (docs/specs/authority-head-vectors.v1.json) are the contract the iOS and
 * Android verifiers will check a published head against, so every byte of them is recomputed here: the
 * canonical bytes, the signature preimage, the deterministic signature, the payload hash the
 * {@code ACCOUNT_AUTHORITY} leaf commits, and every case a conforming decoder must refuse together with the
 * rule that refuses it.
 *
 * <p>Written in the shape of {@link AuthorityVectorsTest}, which does the same job for the chain records, and
 * for the same reason: neither client has ever verified anything cryptographic against the resolver, so this
 * is the first signature either of them will check, and a byte format that only one implementation has ever
 * produced is a format with one implementation.
 *
 * <p>The two files are deliberately joined: the head's {@code headHash} is the record hash of the
 * {@code AdoptRoot} in the chain vectors, so a client that has implemented both can check that the head it
 * would verify is the head that chain reaches.
 *
 * <p>The key is the RFC 8032 section 7.1 TEST 3 constant, which is what makes the signature reproducible. It
 * is a published value and signs nothing real.
 */
class AuthorityHeadVectorsTest {

    private static final Path VECTORS = Path.of("docs/specs/authority-head-vectors.v1.json");
    private static final Path CHAIN_VECTORS = Path.of("docs/specs/authority-vectors.v1.json");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String PKCS8_PREFIX = "302e020100300506032b657004220420";

    @Test
    void theFileNamesTheEncodingTheLeafAndTheMagicTheCodeUses() throws Exception {
        JsonNode root = vectors();

        assertThat(root.path("encoding").asText()).isEqualTo(AuthorityHeadRecord.DOMAIN);
        assertThat(root.path("leafType").asText()).isEqualTo(AuthorityHeadRecord.LEAF_TYPE);
        assertThat(root.path("magic").asText()).isEqualTo(AuthorityHeadRecord.MAGIC);
        assertThat(root.path("layout")).isNotEmpty();
    }

    @Test
    void theCanonicalBytesAreReproducibleFromTheFieldsTheVectorNames() throws Exception {
        JsonNode head = vectors().path("head");

        byte[] encoded = AuthorityHeadRecordCodec.encode(
                HEX.parseHex(vectors().path("account").path("referenceHex").asText()),
                HEX.parseHex(head.path("headHashHex").asText()),
                head.path("headSeq").asLong(),
                head.path("homeserverId").asText(),
                Instant.ofEpochMilli(head.path("issuedAtMillis").asLong()),
                Instant.ofEpochMilli(head.path("notBeforeMillis").asLong()),
                Instant.ofEpochMilli(head.path("notAfterMillis").asLong()));

        assertThat(HEX.formatHex(encoded)).isEqualTo(head.path("canonicalHex").asText());
        assertThat(encoded).hasSize(head.path("length").asInt());
        assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(encoded))
                .isEqualTo(head.path("recordB64").asText());
    }

    @Test
    void thePublishedBase64urlSpellingIsTheOnlyOneThatRoundTrips() throws Exception {
        String recordB64 = vectors().path("head").path("recordB64").asText();

        byte[] decoded = Base64.getUrlDecoder().decode(recordB64);

        // The resolver's placement verifier requires decode-then-re-encode to equal the input before it looks
        // at anything else, so a head has one spelling on the wire as well as one in bytes. Unpadded, and the
        // padded form is a different string.
        assertThat(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)).isEqualTo(recordB64);
        assertThat(recordB64).doesNotContain("=").doesNotContain("+").doesNotContain("/");
    }

    @Test
    void theLeafPayloadHashIsTheSha256OfThoseBytes() throws Exception {
        JsonNode head = vectors().path("head");
        byte[] canonical = HEX.parseHex(head.path("canonicalHex").asText());

        String digest = HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));

        assertThat(digest).isEqualTo(head.path("leafPayloadSha256Hex").asText());
        assertThat(AuthorityHeadRecordCodec.decode(canonical).payloadHashHex())
                .isEqualTo(head.path("leafPayloadSha256Hex").asText());
    }

    @Test
    void thePreimageIsTheMagicThenTheBytesAndTheSignatureIsReproducible() throws Exception {
        JsonNode head = vectors().path("head");
        byte[] canonical = HEX.parseHex(head.path("canonicalHex").asText());

        byte[] preimage = AuthorityHeadRecordCodec.signaturePreimage(canonical);
        assertThat(HEX.formatHex(preimage)).isEqualTo(head.path("signaturePreimageHex").asText());

        PrivateKey key = privateKey(vectors().path("keys").path("rfc8032-test3").path("seedHex").asText());
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(preimage);

        assertThat(Base64.getEncoder().encodeToString(signer.sign()))
                .isEqualTo(head.path("signatureB64").asText());
    }

    @Test
    void theSignatureVerifiesUnderThePublishedRosterKeyAndNotUnderAnother() throws Exception {
        JsonNode head = vectors().path("head");
        byte[] preimage = AuthorityHeadRecordCodec.signaturePreimage(
                HEX.parseHex(head.path("canonicalHex").asText()));
        byte[] signature = Base64.getDecoder().decode(head.path("signatureB64").asText());

        assertThat(me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys.verify(
                HEX.parseHex(head.path("verifyingKeyHex").asText()), preimage, signature)).isTrue();

        // A chain-record preimage over the same bytes must not verify: the magic is the signature domain and
        // it is the only thing separating the two.
        byte[] wrongDomain = HEX.parseHex(head.path("canonicalHex").asText());
        assertThat(me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys.verify(
                HEX.parseHex(head.path("verifyingKeyHex").asText()), wrongDomain, signature)).isFalse();
    }

    @Test
    void theHeadPublishesTheHeadTheChainVectorsReach() throws Exception {
        JsonNode chain = JSON.readTree(Files.readString(CHAIN_VECTORS));
        JsonNode head = vectors().path("head");

        assertThat(vectors().path("account").path("referenceHex").asText())
                .isEqualTo(chain.path("account").path("rawBytesHex").asText());

        JsonNode adoptRoot = null;
        for (JsonNode record : chain.path("records")) {
            if ("GUAA".equals(record.path("magic").asText())) {
                adoptRoot = record;
                break;
            }
        }
        assertThat(adoptRoot).as("the chain vectors carry an AdoptRoot").isNotNull();
        assertThat(head.path("headHashHex").asText()).isEqualTo(adoptRoot.path("sha256Hex").asText());
        assertThat(head.path("headSeq").asLong()).isEqualTo(adoptRoot.path("seq").asLong());
    }

    @Test
    void everyRejectionVectorIsRefusedForTheReasonItNames() throws Exception {
        JsonNode rejections = vectors().path("rejections");
        assertThat(rejections).isNotEmpty();

        for (JsonNode rejection : rejections) {
            byte[] bytes = HEX.parseHex(rejection.path("hex").asText());
            String name = rejection.path("name").asText();

            InvalidAuthorityRecordException thrown = catchThrowableOfType(
                    () -> AuthorityHeadRecordCodec.decode(bytes), InvalidAuthorityRecordException.class);

            assertThat(thrown).as(name + " must be refused").isNotNull();
            assertThat(thrown.reason()).as(name).isEqualTo(rejection.path("reason").asText());
        }
    }

    @Test
    void theRejectionsCoverEveryRuleTheDecoderHas() throws Exception {
        // A rule with no vector is a rule the ports are free to skip, which is how one implementation ends up
        // being the specification.
        java.util.Set<String> reasons = new java.util.HashSet<>();
        for (JsonNode rejection : vectors().path("rejections")) {
            reasons.add(rejection.path("reason").asText());
        }

        assertThat(reasons).containsExactlyInAnyOrder("bad_magic", "unknown_version", "unknown_suite",
                "empty_head_hash", "head_seq_out_of_range", "bad_homeserver_id_length", "wrong_length",
                "bad_homeserver_id", "inverted_window", "window_too_long", "timestamp_out_of_range");
    }

    private static JsonNode vectors() throws Exception {
        assertThat(VECTORS).as("run from the identity-service project directory").isRegularFile();
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static PrivateKey privateKey(String seedHex) throws Exception {
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(HEX.parseHex(PKCS8_PREFIX + seedHex)));
    }
}
