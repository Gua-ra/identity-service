// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

// Keys are decoded on first use, so a malformed key cannot fail startup while publishing is off.
// PlacementSignerStartupCheck decodes them at startup when it is on.
@Component
public class PlacementRecordSigner {

    /** Canonical bytes base64url, signature base64. */
    public record SignedPlacementRecord(String accountId, String homeserverId, String recordB64,
            String signatureB64, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;
    private final FederationIds federationIds;

    private final Map<String, String> configuredKeys = new LinkedHashMap<>();

    private final Map<String, PrivateKey> loadedKeys = new ConcurrentHashMap<>();

    @Autowired
    public PlacementRecordSigner(IdentityServiceProperties properties, FederationIds federationIds) {
        this.properties = properties;
        this.federationIds = federationIds;
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            String key = homeserver.getPlacementSigningPrivateKey();
            if (key == null || key.isBlank()) {
                continue;
            }
            configuredKeys.put(federationIds.of(homeserver), key);
        }
    }

    public PlacementRecordSigner(IdentityServiceProperties properties) {
        this(properties, new FederationIds(properties));
    }

    public boolean canSignFor(String federationId) {
        return configuredKeys.containsKey(federationId);
    }

    public SignedPlacementRecord sign(AccountId accountId, byte origin, String federationId, Instant now) {
        PrivateKey key = signingKey(federationId);
        Duration validity = properties.getPlacement().getRecordValidity();
        Instant notAfter = now.plus(validity);
        byte[] canonical = PlacementRecordCodec.encode(accountId, origin, federationId, now, now, notAfter);
        byte[] signature = Ed25519Keys.sign(key, canonical);
        return new SignedPlacementRecord(
                accountId.value(),
                federationId,
                Base64.getUrlEncoder().withoutPadding().encodeToString(canonical),
                Base64.getEncoder().encodeToString(signature),
                now,
                notAfter);
    }

    private PrivateKey signingKey(String federationId) {
        String configured = configuredKeys.get(federationId);
        if (configured == null) {
            throw new IllegalStateException("No placement signing key is configured for homeserver "
                    + federationId);
        }
        return loadedKeys.computeIfAbsent(federationId,
                id -> Ed25519Keys.privateKeyFromPkcs8(configuredKeys.get(id)));
    }

    public String federationIdOf(HomeserverConfig homeserver) {
        return federationIds.of(homeserver);
    }

    public String federationIdForRegistryId(String registryId) {
        return federationIds.forRegistryId(registryId);
    }
}
