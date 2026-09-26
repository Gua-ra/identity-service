// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.security.PrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecordCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.placement.RosterMembershipKeys;

/**
 * Builds and signs the published authority chain head (ADM-009 decision 12).
 *
 * <p>Signed with the roster membership key of the homeserver that stores the chain, which is the same key a
 * generation-1 placement record is signed with and is held in the one place that key is parsed
 * ({@link RosterMembershipKeys}). The resolver verifies both the same way: it looks the named homeserver up
 * in a roster it has already verified k-of-n, requires that entry to be ACTIVE at acceptance time, and
 * checks the signature under that entry's published signing key.
 *
 * <p><b>What this signature does and does not add, stated rather than implied.</b> It makes a forged head
 * detectable: a third party can no longer be handed a chain head on the word of the service that stores the
 * chain, because the object is signed under a roster identity and the resolver has to have appended a leaf
 * committing it. It does not add an independent party. One identity-service deployment holds the private
 * half of every membership key in its registry, exactly as {@code PlacementRecordSigner}'s javadoc says of
 * itself, so the publisher and the homeserver whose assertion it is are one operator. What the publication
 * adds is a second service, a second key and a second store that a forgery has to pass through as well.
 * "No longer resting solely on the homeserver that stores the chain" is reached; "resting on more than one
 * trust domain" is not, and ADM-005 requirement 12 forbids claiming it before a second operator holds
 * witness keys.
 *
 * <p>No server challenge is inside the signature, which is the one deliberate difference from a chain
 * record: see {@link AuthorityHeadRecordCodec#signaturePreimage(byte[])}.
 */
@Component
public class AuthorityHeadSigner {

    /** The signed envelope as it travels: canonical bytes base64url unpadded, signature base64. */
    public record SignedHead(long headSeq, String headHash, String homeserverId, String recordB64,
            String signatureB64, String payloadHash, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;
    private final RosterMembershipKeys membershipKeys;

    public AuthorityHeadSigner(IdentityServiceProperties properties, RosterMembershipKeys membershipKeys) {
        this.properties = properties;
        this.membershipKeys = membershipKeys;
    }

    /** The roster homeserver this deployment publishes heads under, trimmed, or empty if unconfigured. */
    public String homeserverId() {
        String configured = properties.getAuthority().getPublication().getHomeserverId();
        return configured == null ? "" : configured.trim();
    }

    /** True when the configured homeserver is named and this deployment holds its membership key. */
    public boolean canSign() {
        String homeserverId = homeserverId();
        return !homeserverId.isEmpty() && membershipKeys.holdsKeyFor(homeserverId);
    }

    /**
     * Decodes the configured key, so a malformed one fails the deployment that publishes rather than every
     * transition it runs.
     *
     * <p>Called by {@code AuthorityPublicationStartupCheck} and by nothing else. The key is parsed lazily
     * precisely so that a deployment with publishing off is unaffected by a key it will never use.
     *
     * @throws RuntimeException when the configured key is not a readable Ed25519 private key
     */
    public void verifySigningKey() {
        membershipKeys.signingKey(homeserverId());
    }

    /**
     * Signs an assertion that {@code headHash} at {@code headSeq} is the settled head of that account's
     * chain.
     *
     * @param accountReference the 34 bytes the chain envelope carries, which is all this object says about
     *                         which account it is: a version byte, a class byte and a hash
     * @param headHash         lowercase or uppercase hex of the head record's SHA-256, 64 characters
     * @throws IllegalStateException when no membership key is configured for the homeserver this deployment
     *                               publishes under, which is a deployment error rather than a per-account
     *                               one and is what the startup check exists to catch first
     */
    public SignedHead sign(byte[] accountReference, String headHash, long headSeq, Instant now) {
        String homeserverId = homeserverId();
        if (!canSign()) {
            throw new IllegalStateException("No roster membership signing key is configured for the homeserver "
                    + "identity.authority.publication.homeserver-id names");
        }
        PrivateKey key = membershipKeys.signingKey(homeserverId);
        Duration validity = properties.getAuthority().getPublication().getHeadValidity();
        Instant notAfter = now.plus(validity);
        byte[] rawHeadHash = HexFormat.of().parseHex(headHash.toLowerCase(java.util.Locale.ROOT));
        byte[] canonical = AuthorityHeadRecordCodec.encode(accountReference, rawHeadHash, headSeq, homeserverId,
                now, now, notAfter);
        byte[] signature = Ed25519Keys.sign(key, AuthorityHeadRecordCodec.signaturePreimage(canonical));
        // Decoded back before it leaves, so anything this service could not read is refused here rather than
        // at the far end, and the payload hash is taken from the object that was actually built.
        AuthorityHeadRecord decoded = AuthorityHeadRecordCodec.decode(canonical);
        return new SignedHead(headSeq, decoded.headHashHex(), homeserverId,
                Base64.getUrlEncoder().withoutPadding().encodeToString(canonical),
                Base64.getEncoder().encodeToString(signature),
                decoded.payloadHashHex(), now, notAfter);
    }
}
