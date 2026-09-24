// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
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
 *
 * <h2>Keys are parsed on first use, not at construction</h2>
 * <p>Held and decoded by {@link RosterMembershipKeys}, which is the one place that key is parsed because
 * the published authority head of ADM-009 decision 12 is signed with the same one. This bean is built in
 * every deployment, including the overwhelming majority that have placement publishing switched off, so
 * parsing a configured key eagerly would mean a deployment holding a malformed or truncated key in its
 * Secret failed to start even with the feature off, which is a behaviour change the flags are supposed to
 * prevent. A deployment that does publish still gets its keys checked before it serves anything:
 * {@link PlacementSignerStartupCheck} decodes every one of them at startup and refuses to start if any
 * fails, which is the fail-fast that matters.
 */
@Component
public class PlacementRecordSigner {

    /** The signed envelope as it travels: canonical bytes base64url, signature base64. */
    public record SignedPlacementRecord(String accountId, String homeserverId, String recordB64,
            String signatureB64, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;
    private final FederationIds federationIds;
    private final RosterMembershipKeys membershipKeys;

    @Autowired
    public PlacementRecordSigner(IdentityServiceProperties properties, FederationIds federationIds,
            RosterMembershipKeys membershipKeys) {
        this.properties = properties;
        this.federationIds = federationIds;
        this.membershipKeys = membershipKeys;
    }

    /** For callers that build the signer directly rather than through the container. */
    public PlacementRecordSigner(IdentityServiceProperties properties) {
        this(properties, new FederationIds(properties), new RosterMembershipKeys(properties));
    }

    /** True when this deployment holds a signing key for that roster homeserver id. */
    public boolean canSignFor(String federationId) {
        return membershipKeys.holdsKeyFor(federationId);
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
        if (!membershipKeys.holdsKeyFor(federationId)) {
            throw new IllegalStateException("No placement signing key is configured for homeserver "
                    + federationId);
        }
        return membershipKeys.signingKey(federationId);
    }

    /**
     * The roster id a configured homeserver publishes under.
     *
     * <p>Delegates to {@link FederationIds}, which is the single implementation of this mapping. The MAS
     * readers resolve the same value through the same collaborator, so the id the comparison indexes by
     * and the id a reader reports can no longer disagree.
     */
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
