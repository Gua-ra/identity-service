// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * Builds and signs generation-1 placement records (ADM-008 decision 7).
 *
 * <p>identity-service signs as the provisioning agent it already is for each homeserver in its registry:
 * it holds their admin tokens, and under decision 7 it holds the private half of their roster membership
 * keys until Phase 1 genesis keys and Phase 2 registries replace that arrangement. The format does not
 * change when they do; only where the verifier looks the key up.
 *
 * <p>One consequence is stated rather than hidden: one signer for every homeserver is one operator, able
 * to produce roster-level proofs for each key, so generation-1 records improve no compromise condition.
 * They record where an account already lives.
 */
@Component
public class PlacementRecordSigner {

    /** The signed envelope as it travels: canonical bytes base64url, signature base64. */
    public record SignedPlacementRecord(String accountId, String homeserverId, String recordB64,
            String signatureB64, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;

    /** Federation roster id to the private half of that homeserver's membership key. */
    private final Map<String, PrivateKey> signingKeys = new LinkedHashMap<>();

    /** Local registry id to federation roster id, for the configured homeservers. */
    private final Map<String, String> federationIdByRegistryId = new LinkedHashMap<>();

    public PlacementRecordSigner(IdentityServiceProperties properties) {
        this.properties = properties;
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            federationIdByRegistryId.put(homeserver.getId(), federationIdOf(homeserver));
            String key = homeserver.getPlacementSigningPrivateKey();
            if (key == null || key.isBlank()) {
                // A homeserver this deployment does not publish for. Loading nothing here is what keeps
                // construction free of side effects while the feature is switched off.
                continue;
            }
            signingKeys.put(federationIdOf(homeserver), Ed25519Keys.privateKeyFromPkcs8(key));
        }
    }

    /** True when this deployment holds a signing key for that roster homeserver id. */
    public boolean canSignFor(String federationId) {
        return signingKeys.containsKey(federationId);
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
        PrivateKey key = signingKeys.get(federationId);
        if (key == null) {
            throw new IllegalStateException("No placement signing key is configured for homeserver "
                    + federationId);
        }
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

    /**
     * The roster id a configured homeserver publishes under: its explicit {@code federationId}, else the
     * alias configured for its local registry id, else the local id itself.
     */
    public String federationIdOf(HomeserverConfig homeserver) {
        String explicit = homeserver.getFederationId();
        if (explicit != null && !explicit.isBlank()) {
            return explicit.trim();
        }
        return aliasOrSelf(homeserver.getId());
    }

    /**
     * Maps a value out of {@code directory_entries.homeserver_id} to a federation roster id, for
     * comparison only.
     *
     * <p>A configured homeserver answers for itself, which is the ordinary case: the directory holds
     * this deployment's local registry ids and each configured homeserver knows its own roster id. The
     * alias map is for the values that match no configured homeserver, which in practice means the
     * legacy synthesised id and the rows written before routing existed. Getting this wrong produces
     * false stale-directory findings and nothing worse, because publishing uses the MAS link and never
     * this value.
     */
    public String federationIdForRegistryId(String registryId) {
        if (registryId == null || registryId.isBlank()) {
            return null;
        }
        String configured = federationIdByRegistryId.get(registryId);
        return configured != null ? configured : aliasOrSelf(registryId);
    }

    private String aliasOrSelf(String registryId) {
        return Optional.ofNullable(properties.getPlacement().getFederationIdAliases().get(registryId))
                .filter(alias -> !alias.isBlank())
                .orElse(registryId);
    }
}
