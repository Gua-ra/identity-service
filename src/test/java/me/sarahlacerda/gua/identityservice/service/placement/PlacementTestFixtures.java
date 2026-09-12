// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * Shared scaffolding for the placement tests: a configured homeserver with a throwaway membership key.
 * Every key is generated in memory for the duration of one test; nothing here reads a secret.
 */
final class PlacementTestFixtures {

    /** Reserved documentation domain, so no real host name appears in a test. */
    static final String DOMAIN = "example.test";
    static final String LOCAL_ID = "primary";
    static final String FEDERATION_ID = "fed-primary";

    private PlacementTestFixtures() {
    }

    static TestEd25519.Pair keyPair() {
        return TestEd25519.generate();
    }

    static String pkcs8(TestEd25519.Pair pair) {
        return Base64.getEncoder().encodeToString(pair.privateKey().getEncoded());
    }

    static String publicKeyBase64(TestEd25519.Pair pair) {
        return Base64.getEncoder().encodeToString(pair.rawPublicKey());
    }

    static HomeserverConfig homeserver(String localId, String domain, String federationId, String signingKey) {
        HomeserverConfig homeserver = new HomeserverConfig();
        homeserver.setId(localId);
        homeserver.setDomain(domain);
        homeserver.setAdminApiBaseUrl("http://admin.invalid");
        homeserver.setClientApiBaseUrl("http://client.invalid");
        homeserver.setAdminAccessToken("not-a-real-token");
        homeserver.setFederationId(federationId);
        homeserver.setPlacementSigningPrivateKey(signingKey);
        return homeserver;
    }

    /** Properties carrying exactly one homeserver this deployment holds the membership key for. */
    static IdentityServiceProperties propertiesWithOneHomeserver(TestEd25519.Pair pair) {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getRouting().getHomeservers()
                .add(homeserver(LOCAL_ID, DOMAIN, FEDERATION_ID, pkcs8(pair)));
        properties.getPlacement().setResolverBaseUrl("http://resolver.invalid");
        return properties;
    }

    static AccountId genesisRootedId(String seed) {
        return AccountId.derive(AccountId.CLASS_GENESIS, seed.getBytes(StandardCharsets.UTF_8));
    }

    static AccountId bootstrapId(String seed) {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, seed.getBytes(StandardCharsets.UTF_8));
    }
}
