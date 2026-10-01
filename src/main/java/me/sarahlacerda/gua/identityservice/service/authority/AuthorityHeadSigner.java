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

/** Signs with the homeserver's roster membership key, the same key that signs placement records. */
@Component
public class AuthorityHeadSigner {

    public record SignedHead(long headSeq, String headHash, String homeserverId, String recordB64,
            String signatureB64, String payloadHash, Instant issuedAt, Instant notAfter) {
    }

    private final IdentityServiceProperties properties;
    private final RosterMembershipKeys membershipKeys;

    public AuthorityHeadSigner(IdentityServiceProperties properties, RosterMembershipKeys membershipKeys) {
        this.properties = properties;
        this.membershipKeys = membershipKeys;
    }

    public String homeserverId() {
        String configured = properties.getAuthority().getPublication().getHomeserverId();
        return configured == null ? "" : configured.trim();
    }

    public boolean canSign() {
        String homeserverId = homeserverId();
        return !homeserverId.isEmpty() && membershipKeys.holdsKeyFor(homeserverId);
    }

    public void verifySigningKey() {
        membershipKeys.signingKey(homeserverId());
    }

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
        // Decoded back so a head this service could not read is refused before it leaves.
        AuthorityHeadRecord decoded = AuthorityHeadRecordCodec.decode(canonical);
        return new SignedHead(headSeq, decoded.headHashHex(), homeserverId,
                Base64.getUrlEncoder().withoutPadding().encodeToString(canonical),
                Base64.getEncoder().encodeToString(signature),
                decoded.payloadHashHex(), now, notAfter);
    }
}
