// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecord;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The signer: it produces bytes that verify under the homeserver's own roster membership key. */
class PlacementRecordSignerTest {

    private final TestEd25519.Pair pair = PlacementTestFixtures.keyPair();
    private final IdentityServiceProperties properties =
            PlacementTestFixtures.propertiesWithOneHomeserver(pair);
    private final PlacementRecordSigner signer = new PlacementRecordSigner(properties);

    private final Instant now = Instant.parse("2026-09-11T12:00:00Z");

    @Test
    void aSignedRecordVerifiesUnderTheHomeserversRosterKey() {
        AccountId accountId = PlacementTestFixtures.genesisRootedId("account-one");

        PlacementRecordSigner.SignedPlacementRecord signed =
                signer.sign(accountId, AccountId.CLASS_GENESIS, PlacementTestFixtures.FEDERATION_ID, now);

        byte[] canonical = Base64.getUrlDecoder().decode(signed.recordB64());
        byte[] signature = Base64.getDecoder().decode(signed.signatureB64());
        assertThat(Ed25519Keys.verify(pair.rawPublicKey(), canonical, signature)).isTrue();

        PlacementRecord decoded = PlacementRecordCodec.decode(canonical);
        assertThat(decoded.accountId()).isEqualTo(accountId);
        assertThat(decoded.homeserverId()).isEqualTo(PlacementTestFixtures.FEDERATION_ID);
        assertThat(decoded.generation()).isEqualTo(PlacementRecord.GENERATION_ONE);
    }

    @Test
    void anotherMembersKeyDoesNotVerifyIt() {
        TestEd25519.Pair other = PlacementTestFixtures.keyPair();
        PlacementRecordSigner.SignedPlacementRecord signed = signer.sign(
                PlacementTestFixtures.genesisRootedId("account-two"), AccountId.CLASS_GENESIS,
                PlacementTestFixtures.FEDERATION_ID, now);

        assertThat(Ed25519Keys.verify(other.rawPublicKey(),
                Base64.getUrlDecoder().decode(signed.recordB64()),
                Base64.getDecoder().decode(signed.signatureB64()))).isFalse();
    }

    @Test
    void theValidityWindowIsTheConfiguredFourHundredDays() {
        assertThat(properties.getPlacement().getRecordValidity()).isEqualTo(Duration.ofDays(400));
        assertThat(properties.getPlacement().getReissueAfter()).isEqualTo(Duration.ofDays(300));

        PlacementRecordSigner.SignedPlacementRecord signed = signer.sign(
                PlacementTestFixtures.genesisRootedId("account-three"), AccountId.CLASS_GENESIS,
                PlacementTestFixtures.FEDERATION_ID, now);

        PlacementRecord decoded = PlacementRecordCodec.decode(Base64.getUrlDecoder().decode(signed.recordB64()));
        assertThat(decoded.issuedAt()).isEqualTo(now);
        assertThat(decoded.notBefore()).isEqualTo(now);
        assertThat(decoded.notAfter()).isEqualTo(now.plus(Duration.ofDays(400)));
    }

    @Test
    void aBootstrapAccountIsSignedWithTheBootstrapOrigin() {
        AccountId bootstrap = PlacementTestFixtures.bootstrapId("account-four");

        PlacementRecordSigner.SignedPlacementRecord signed =
                signer.sign(bootstrap, AccountId.CLASS_BOOTSTRAP, PlacementTestFixtures.FEDERATION_ID, now);

        PlacementRecord decoded = PlacementRecordCodec.decode(Base64.getUrlDecoder().decode(signed.recordB64()));
        assertThat(decoded.isGenesisRooted()).isFalse();
    }

    @Test
    void aHomeserverThisDeploymentHoldsNoKeyForCannotBeSignedFor() {
        assertThat(signer.canSignFor(PlacementTestFixtures.FEDERATION_ID)).isTrue();
        assertThat(signer.canSignFor("fed-elsewhere")).isFalse();

        assertThatThrownBy(() -> signer.sign(PlacementTestFixtures.genesisRootedId("account-five"),
                AccountId.CLASS_GENESIS, "fed-elsewhere", now))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No placement signing key");
    }

    @Test
    void aHomeserverWithNoConfiguredKeyLoadsNothingAtAll() {
        IdentityServiceProperties bare = new IdentityServiceProperties();
        bare.getRouting().getHomeservers().add(PlacementTestFixtures.homeserver("other",
                "other.example.test", "fed-other", ""));

        PlacementRecordSigner bareSigner = new PlacementRecordSigner(bare);

        assertThat(bareSigner.canSignFor("fed-other")).isFalse();
    }

    @Test
    void theAliasMapOnlyFillsInAMissingFederationId() {
        IdentityServiceProperties aliased = new IdentityServiceProperties();
        aliased.getPlacement().getFederationIdAliases().put("default", "fed-legacy");
        PlacementRecordSigner aliasSigner = new PlacementRecordSigner(aliased);

        // A legacy directory value maps through the alias.
        assertThat(aliasSigner.federationIdForRegistryId("default")).isEqualTo("fed-legacy");
        // Anything without an alias is used as-is rather than guessed at.
        assertThat(aliasSigner.federationIdForRegistryId("primary")).isEqualTo("primary");
        assertThat(aliasSigner.federationIdForRegistryId(null)).isNull();
        // An explicit federation id always wins over the alias map.
        assertThat(aliasSigner.federationIdOf(PlacementTestFixtures.homeserver("default",
                PlacementTestFixtures.DOMAIN, "fed-explicit", ""))).isEqualTo("fed-explicit");
    }

    @Test
    void aMalformedSigningKeyIsNotParsedUntilARecordIsActuallySigned() {
        IdentityServiceProperties malformed = new IdentityServiceProperties();
        malformed.getRouting().getHomeservers().add(PlacementTestFixtures.homeserver(
                PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.FEDERATION_ID, "this is not a key"));

        // This bean is built in every deployment, including the great majority with publishing off,
        // where nothing will ever sign. Parsing eagerly meant a malformed Secret stopped the service
        // starting even with the feature off, which is a behaviour change the flags exist to prevent.
        PlacementRecordSigner lazy = new PlacementRecordSigner(malformed);

        assertThat(lazy.canSignFor(PlacementTestFixtures.FEDERATION_ID)).isTrue();
        assertThatThrownBy(() -> lazy.sign(PlacementTestFixtures.genesisRootedId("account-six"),
                AccountId.CLASS_GENESIS, PlacementTestFixtures.FEDERATION_ID, now))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void theSignerResolvesRosterIdsThroughTheOneSharedImplementation() {
        IdentityServiceProperties aliased = new IdentityServiceProperties();
        aliased.getPlacement().getFederationIdAliases().put("legacy", "fed-legacy");
        HomeserverConfig noExplicitId = PlacementTestFixtures.homeserverWithoutFederationId("legacy",
                PlacementTestFixtures.DOMAIN, "");
        aliased.getRouting().getHomeservers().add(noExplicitId);

        // The MAS readers resolve the same value through the same collaborator, so the id a reader
        // reports and the id the comparison indexes by cannot drift apart again.
        assertThat(new PlacementRecordSigner(aliased).federationIdOf(noExplicitId))
                .isEqualTo(new FederationIds(aliased).of(noExplicitId))
                .isEqualTo("fed-legacy");
    }
}
