package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The published golden vectors (docs/specs/genesis-vectors.v1.json) are the contract the iOS and
 * Android ports and gua-resolver verify against, so every byte of them is recomputed here: canonical
 * bytes, object hashes, accountIds, the two deterministic proof signatures, and every case a conforming
 * decoder must refuse together with the rule that refuses it.
 *
 * <p>The keys are the RFC 8032 section 7.1 test constants, which is what lets the signatures be
 * reproducible. They are published values and sign nothing real.
 */
class GenesisVectorsTest {

    private static final Path VECTORS = Path.of("docs/specs/genesis-vectors.v1.json");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String PKCS8_PREFIX = "302e020100300506032b657004220420";

    private static JsonNode vectors() throws Exception {
        return JSON.readTree(Files.readString(VECTORS));
    }

    private static PrivateKey privateKey(String seedHex) throws Exception {
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(HEX.parseHex(PKCS8_PREFIX + seedHex)));
    }

    private static String sign(String seedHex, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey(seedHex));
        signature.update(message);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static String seedOf(JsonNode root, String publicKeyHex) {
        for (JsonNode key : root.get("keys")) {
            if (key.get("publicKeyHex").asText().equals(publicKeyHex)) {
                return key.get("seedHex").asText();
            }
        }
        throw new IllegalStateException("the vectors name a key they do not publish");
    }

    @Test
    void theFileIsPresentAndNamesTheDecisionItImplements() throws Exception {
        JsonNode root = vectors();

        assertThat(root.get("encoding").asText()).isEqualTo("gua-account-objects.v1");
        assertThat(root.get("decision").asText()).contains("ADM-008");
        assertThat(root.get("accountGenesis")).isNotEmpty();
        assertThat(root.get("bootstrapGenesis")).isNotEmpty();
    }

    @Test
    void everyAccountGenesisVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode vector : root.get("accountGenesis")) {
            String name = vector.get("name").asText();
            byte[] canonical = HEX.parseHex(vector.get("canonicalHex").asText());

            byte[] encoded = AccountGenesisCodec.encode(
                    HEX.parseHex(vector.get("authorityPublicKeyHex").asText()),
                    vector.get("recoveryFrameworkId").asInt(),
                    HEX.parseHex(vector.get("recoveryAuthorityPublicKeyHex").asText()),
                    HEX.parseHex(vector.get("entropyHex").asText()));
            assertThat(HEX.formatHex(encoded)).as(name).isEqualTo(vector.get("canonicalHex").asText());

            AccountGenesis genesis = AccountGenesisCodec.decode(canonical);
            assertThat(genesis.genesisVersion()).as(name).isEqualTo(vector.get("genesisVersion").asInt());
            assertThat(genesis.suite()).as(name).isEqualTo(vector.get("suite").asInt());
            assertThat(HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(canonical)))
                    .as(name).isEqualTo(vector.get("sha256Hex").asText());
            assertThat(genesis.accountId().value()).as(name).isEqualTo(vector.get("accountId").asText());

            // Deterministic Ed25519: the published proof is reproducible, and it verifies.
            String seed = seedOf(root, vector.get("authorityPublicKeyHex").asText());
            String signature = sign(seed, GenesisProofs.genesisProofPreimage(canonical));
            assertThat(signature).as(name).isEqualTo(vector.get("genesisProofSignatureB64").asText());
            assertThat(GenesisProofs.verifyGenesisProof(genesis,
                    Base64.getDecoder().decode(vector.get("genesisProofSignatureB64").asText())))
                    .as(name).isTrue();
        }
    }

    @Test
    void everyBootstrapGenesisVectorReproduces() throws Exception {
        JsonNode root = vectors();
        for (JsonNode vector : root.get("bootstrapGenesis")) {
            String name = vector.get("name").asText();
            byte[] canonical = HEX.parseHex(vector.get("canonicalHex").asText());

            assertThat(HEX.formatHex(BootstrapGenesisCodec.encode(HEX.parseHex(vector.get("entropyHex").asText()))))
                    .as(name).isEqualTo(vector.get("canonicalHex").asText());

            BootstrapGenesis genesis = BootstrapGenesisCodec.decode(canonical);
            assertThat(HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(canonical)))
                    .as(name).isEqualTo(vector.get("sha256Hex").asText());
            assertThat(genesis.accountId().value()).as(name).isEqualTo(vector.get("accountId").asText());
            assertThat(genesis.accountId().rootClass()).as(name).isEqualTo(AccountId.CLASS_BOOTSTRAP);
        }
    }

    @Test
    void theAttachProofVectorReproduces() throws Exception {
        JsonNode root = vectors();
        JsonNode vector = root.get("attachProof");

        assertThat(vector.get("domain").asText()).isEqualTo(GenesisProofs.ATTACH_PROOF_DOMAIN);
        assertThat(vector.get("domainLength").asInt()).isEqualTo(27);
        assertThat(vector.get("preimageLength").asInt()).isEqualTo(GenesisProofs.ATTACH_PREIMAGE_LENGTH).isEqualTo(93);

        AccountId accountId = AccountId.parse(vector.get("accountId").asText());
        assertThat(HEX.formatHex(accountId.rawBytes())).isEqualTo(vector.get("accountIdRawHex").asText());

        byte[] challenge = HEX.parseHex(vector.get("challengeHex").asText());
        byte[] preimage = GenesisProofs.attachProofPreimage(challenge, accountId);
        assertThat(HEX.formatHex(preimage)).isEqualTo(vector.get("preimageHex").asText());

        JsonNode genesisVector = root.get("accountGenesis").get(0);
        String seed = seedOf(root, genesisVector.get("authorityPublicKeyHex").asText());
        assertThat(sign(seed, preimage)).isEqualTo(vector.get("signatureB64").asText());
        assertThat(GenesisProofs.verifyAttachProof(
                HEX.parseHex(genesisVector.get("authorityPublicKeyHex").asText()),
                challenge, accountId,
                Base64.getDecoder().decode(vector.get("signatureB64").asText()))).isTrue();
    }

    @Test
    void theAccountIdRulesMatchTheImplementation() throws Exception {
        JsonNode rules = vectors().get("accountId");

        assertThat(rules.get("pattern").asText()).isEqualTo(AccountId.CANONICAL_PATTERN);
        assertThat(rules.get("rawLength").asInt()).isEqualTo(AccountId.RAW_LENGTH);
        assertThat(rules.get("totalLength").asInt()).isEqualTo(AccountId.LENGTH);
        assertThat(rules.get("rootClassGenesis").asInt()).isEqualTo(AccountId.CLASS_GENESIS);
        assertThat(rules.get("rootClassBootstrap").asInt()).isEqualTo(AccountId.CLASS_BOOTSTRAP);
    }

    @Test
    void everyPublishedRejectionIsRefusedByTheNamedRule() throws Exception {
        JsonNode rejections = vectors().get("rejections");

        for (JsonNode vector : rejections.get("accountGenesis")) {
            byte[] bytes = HEX.parseHex(vector.get("hex").asText());
            assertThatThrownBy(() -> AccountGenesisCodec.decode(bytes))
                    .as(vector.get("name").asText())
                    .isInstanceOf(InvalidGenesisException.class)
                    .extracting(e -> ((InvalidGenesisException) e).reason())
                    .isEqualTo(vector.get("reason").asText());
        }
        for (JsonNode vector : rejections.get("bootstrapGenesis")) {
            byte[] bytes = HEX.parseHex(vector.get("hex").asText());
            assertThatThrownBy(() -> BootstrapGenesisCodec.decode(bytes))
                    .as(vector.get("name").asText())
                    .isInstanceOf(InvalidGenesisException.class)
                    .extracting(e -> ((InvalidGenesisException) e).reason())
                    .isEqualTo(vector.get("reason").asText());
        }
        for (JsonNode vector : rejections.get("accountId")) {
            String value = vector.get("value").asText();
            assertThatThrownBy(() -> AccountId.parse(value))
                    .as(vector.get("name").asText())
                    .isInstanceOf(InvalidGenesisException.class)
                    .extracting(e -> ((InvalidGenesisException) e).reason())
                    .isEqualTo(vector.get("reason").asText());
        }
    }

    @Test
    void theRejectionListCoversEveryRuleTheDecisionStates() throws Exception {
        JsonNode rejections = vectors().get("rejections");
        java.util.Set<String> reasons = new java.util.HashSet<>();
        rejections.get("accountGenesis").forEach(v -> reasons.add(v.get("reason").asText()));

        assertThat(reasons).contains("wrong_length", "bad_magic", "unknown_version", "unknown_suite",
                "unknown_recovery_framework", "zero_authority_key", "zero_recovery_key", "duplicate_keys",
                "invalid_authority_key", "invalid_recovery_key");
    }
}
