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

/**
 * Builds and signs generation-1 placement records.
 *
 * <p>identity-service signs as the provisioning agent for each homeserver in its registry: it holds
 * the private half of their roster membership keys. One signer for every homeserver is one
 * operator, so these records improve no compromise condition; they record where an account lives.
 *
 * <p>Keys are decoded on first use, not at construction: this bean is built in every deployment,
 * and a malformed key must not fail startup while publishing is off. A deployment that does publish
 * gets its keys checked at startup by {@link PlacementSignerStartupCheck}.
 */
@Component
public class PlacementRecordSigner {

    /** The signed envelope as it travels: canonical bytes base64url, signature base64. */
    public record SignedPlacementRecord(String accountId, String homeserverId, String recordB64,
            String signatureB64, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;
    private final FederationIds federationIds;

    /** Federation roster id to the configured base64 PKCS#8 text of that homeserver's membership key. */
    private final Map<String, String> configuredKeys = new LinkedHashMap<>();

    /** The decoded halves, populated on first use. */
    private final Map<String, PrivateKey> loadedKeys = new ConcurrentHashMap<>();

    @Autowired
    public PlacementRecordSigner(IdentityServiceProperties properties, FederationIds federationIds) {
        this.properties = properties;
        this.federationIds = federationIds;
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            String key = homeserver.getPlacementSigningPrivateKey();
            if (key == null || key.isBlank()) {
                // A homeserver this deployment does not publish for.
                continue;
            }
            configuredKeys.put(federationIds.of(homeserver), key);
        }
    }

    /** For callers that build the signer directly rather than through the container. */
    public PlacementRecordSigner(IdentityServiceProperties properties) {
        this(properties, new FederationIds(properties));
    }

    /** True when this deployment holds a signing key for that roster homeserver id. */
    public boolean canSignFor(String federationId) {
        return configuredKeys.containsKey(federationId);
    }

    /**
     * Signs a record placing {@code accountId} on {@code federationId}.
     *
     * @param origin the account's root class, taken from its genesis row; the codec refuses a record
     *               whose origin byte disagrees with the class byte inside the accountId
     * @throws IllegalStateException when no signing key is configured for that homeserver, which is a
     *                               deployment error rather than a per-account one
     */
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

    /** The roster id a configured homeserver publishes under. Delegates to {@link FederationIds}. */
    public String federationIdOf(HomeserverConfig homeserver) {
        return federationIds.of(homeserver);
    }

    /**
     * Maps a value out of {@code directory_entries.homeserver_id} to a federation roster id, for
     * comparison only. Delegates to {@link FederationIds}.
     */
    public String federationIdForRegistryId(String registryId) {
        return federationIds.forRegistryId(registryId);
    }
}
