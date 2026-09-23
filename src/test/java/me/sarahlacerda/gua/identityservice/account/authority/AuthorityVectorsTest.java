// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The published golden vectors (docs/specs/authority-vectors.v1.json) are the contract the iOS and Android
 * ports verify the authority chain against, so every byte of them is recomputed here: canonical bytes, record
 * hashes, the preimage of the one rule every type obeys, the deterministic signatures, and every case a
 * conforming decoder must refuse together with the rule that refuses it.
 *
 * <p>Written in the shape of {@code GenesisVectorsTest}, which does the same job for the account objects, and
 * for the same reason: a cross-platform byte format that only one implementation has ever produced is a
 * format with one implementation. Three ports have to agree on 177, 161, 145, 209 and 144 bytes, on which
 * field sits at which offset, and on what a decoder refuses; a file each of them checks is how that agreement
 * is testable rather than asserted.
 *
 * <p>The keys are the RFC 8032 section 7.1 test constants, which is what makes the signatures reproducible.
 * They are published values and sign nothing real.
 */
class AuthorityVectorsTest {

    private static final Path VECTORS = Path.of("docs/specs/authority-vectors.v1.json");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String PKCS8_PREFIX = "302e020100300506032b657004220420";

    @Test
    void theVectorsCoverEveryRecordTypeTheChainHas() throws Exception {
        JsonNode root = vectors();

        // The point of the file is that a client can check itself against all of it. A type with no vector is
        // a type each port implements from the prose and nobody compares.
        for (AuthorityRecordType type : AuthorityRecordType.values()) {
            assertThat(magics(root)).as("a vector for %s", type).contains(type.magic());
        }
    }

    @Test
    void theAccountReferenceIsTheOneItsAccountIdDerivesTo() throws Exception {
        JsonNode account = vectors().get("account");

        AccountId derived = AccountId.derive((byte) account.get("rootClass").asInt(),
                HEX.parseHex(account.get("entropyHex").asText()));

        // The 34 bytes at offset 6 of every envelope are exactly what AccountId.rawBytes() returns, so a
        // client that builds them some other way builds records this server refuses.
        assertThat(derived.value()).isEqualTo(account.get("accountId").asText());
        assertThat(HEX.formatHex(derived.rawBytes())).isEqualTo(account.get("rawBytesHex").asText());
    }

    @Test
    void everyRecordDecodesToWhatItSaysItIs() throws Exception {
        JsonNode root = vectors();

        for (JsonNode vector : root.get("records")) {
            byte[] canonical = HEX.parseHex(vector.get("canonicalHex").asText());
            AuthorityRecord record = AuthorityRecordCodec.decode(canonical);

            assertThat(canonical).as("%s length", vector.get("name").asText())
                    .hasSize(vector.get("length").asInt());
            assertThat(record.type().magic()).isEqualTo(vector.get("magic").asText());
            assertThat(record.seq()).isEqualTo(vector.get("seq").asLong());
            assertThat(record.hashHex()).isEqualTo(vector.get("sha256Hex").asText());
            assertThat(HEX.formatHex(record.verifyingKey())).isEqualTo(vector.get("verifyingKeyHex").asText());
            assertThat(record.accountReference())
                    .isEqualTo(HEX.parseHex(root.get("account").get("rawBytesHex").asText()));
        }
    }

    @Test
    void everySignatureIsReproducibleFromItsKeyAndItsPreimage() throws Exception {
        JsonNode root = vectors();
        byte[] challenge = HEX.parseHex(root.get("challengeHex").asText());

        for (JsonNode vector : root.get("records")) {
            byte[] canonical = HEX.parseHex(vector.get("canonicalHex").asText());
            AuthorityRecord record = AuthorityRecordCodec.decode(canonical);
            byte[] preimage = AuthorityProofs.recordPreimage(record.type(), challenge, canonical);

            // The one preimage rule, checked as bytes rather than as prose: magic, then the challenge, then
            // the canonical bytes, in that order and nothing between them.
            assertThat(HEX.formatHex(sha256(preimage))).as("%s preimage", vector.get("name").asText())
                    .isEqualTo(vector.get("preimageSha256Hex").asText());
            assertThat(preimage).startsWith(record.type().magic().getBytes(StandardCharsets.US_ASCII));

            String expected = vector.get("signatureB64").asText();
            assertThat(sign(seedOf(root, vector.get("verifyingKeyHex").asText()), preimage)).isEqualTo(expected);
            assertThat(AuthorityProofs.verifyRecord(record, challenge, Base64.getDecoder().decode(expected)))
                    .as("%s verifies", vector.get("name").asText())
                    .isTrue();
        }
    }

    @Test
    void aSignatureDoesNotVerifyAgainstAnotherChallenge() throws Exception {
        JsonNode root = vectors();
        byte[] otherChallenge = sha256("not the challenge these were signed against".getBytes(StandardCharsets.UTF_8));

        for (JsonNode vector : root.get("records")) {
            AuthorityRecord record = AuthorityRecordCodec.decode(HEX.parseHex(vector.get("canonicalHex").asText()));
            byte[] signature = Base64.getDecoder().decode(vector.get("signatureB64").asText());

            // The whole reason the challenge is inside the signature rather than checked beside it: a captured
            // record is not resubmittable, not precomputable elsewhere, and not transferable.
            assertThat(AuthorityProofs.verifyRecord(record, otherChallenge, signature))
                    .as("%s must not verify under another challenge", vector.get("name").asText())
                    .isFalse();
        }
    }

    @Test
    void everyRejectionIsRefusedByTheRuleItNames() throws Exception {
        for (JsonNode vector : vectors().get("rejections")) {
            byte[] bytes = HEX.parseHex(vector.get("hex").asText());

            InvalidAuthorityRecordException refusal = org.assertj.core.api.Assertions.catchThrowableOfType(
                    () -> AuthorityRecordCodec.decode(bytes), InvalidAuthorityRecordException.class);

            assertThat(refusal).as("%s must be refused", vector.get("name").asText()).isNotNull();
            assertThat(refusal.reason()).as("%s", vector.get("name").asText())
                    .isEqualTo(vector.get("reason").asText());
        }
    }

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static java.util.List<String> magics(JsonNode root) {
        java.util.List<String> magics = new java.util.ArrayList<>();
        root.get("records").forEach(vector -> magics.add(vector.get("magic").asText()));
        return magics;
    }

    private static String seedOf(JsonNode root, String publicKeyHex) {
        for (JsonNode key : root.get("keys")) {
            if (key.get("publicKeyHex").asText().equals(publicKeyHex)) {
                return key.get("seedHex").asText();
            }
        }
        throw new IllegalStateException("the vectors name a key they do not publish");
    }

    private static String sign(String seedHex, byte[] message) throws Exception {
        PrivateKey key = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(HEX.parseHex(PKCS8_PREFIX + seedHex)));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key);
        signature.update(message);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}
