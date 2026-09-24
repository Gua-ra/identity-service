// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecordCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.PublicationProperties;

/**
 * Refuses to start a deployment that would publish authority heads it cannot publish honestly.
 *
 * <p>The same shape as {@link me.sarahlacerda.gua.identityservice.service.placement.PlacementSignerStartupCheck}
 * and {@link AuthorityNotificationGate}: a prerequisite that is missing makes the deployment refuse to start
 * rather than degrade. A publication path that quietly does nothing is worse than one that is off, because
 * the gap decision 12 names looks closed from the outside while every head is being skipped.
 *
 * <p>Four things are checked, and each one is a way of publishing a head that would be a lie or a no-op: no
 * homeserver named, so the signed object would have no roster identity to be verified under; no membership key
 * for the homeserver named, so nothing could be signed at all; a window longer than the codec will encode, so
 * every head would throw at signing time; and a re-issue interval that is not shorter than the window, so an
 * attestation would reach its expiry before it was ever refreshed.
 *
 * <p>Deliberately not checked here: that the roster entry exists and is ACTIVE, and that the configured key is
 * the private half of the key it publishes. {@code PlacementSignerStartupCheck} already reads the roster to
 * make exactly those two checks about exactly this key, so a deployment publishing heads and placements
 * verifies its roster identity once rather than twice. A deployment that publishes heads and not placements
 * does not verify it, which is stated in that check's own terms and is why the resolver verifies every head
 * against the roster at acceptance time regardless.
 *
 * <p>Inert unless {@code identity.authority.publication.enabled} is on.
 */
@Component
public class AuthorityPublicationStartupCheck {

    private static final Logger log = LoggerFactory.getLogger(AuthorityPublicationStartupCheck.class);

    private final IdentityServiceProperties properties;
    private final AuthorityHeadSigner signer;
    private final ResolverAuthorityHeadClient resolver;

    public AuthorityPublicationStartupCheck(IdentityServiceProperties properties, AuthorityHeadSigner signer,
            ResolverAuthorityHeadClient resolver) {
        this.properties = properties;
        this.signer = signer;
        this.resolver = resolver;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void verifyAuthorityPublication() {
        PublicationProperties publication = properties.getAuthority().getPublication();
        if (!publication.isEnabled()) {
            return;
        }
        if (!properties.getAuthority().isEnabled()) {
            throw new IllegalStateException(refusal("identity.authority.enabled is off, so there is no chain "
                    + "to publish a head of. Publishing is a separate switch so the chain can run "
                    + "unpublished, not so a head can be published without one"));
        }
        if (signer.homeserverId().isEmpty()) {
            throw new IllegalStateException(refusal("identity.authority.publication.homeserver-id is not set. "
                    + "A head carries the federation roster id of the homeserver asserting it, and the "
                    + "resolver verifies the signature under that entry's published key, so there is no id a "
                    + "head could name"));
        }
        if (!signer.canSign()) {
            throw new IllegalStateException(refusal("no configured homeserver has the federation roster id '"
                    + signer.homeserverId() + "' with a roster membership signing key, so no head could ever "
                    + "be signed. Configure identity.routing.homeservers[] with that federation-id and its "
                    + "placement signing key, which is the same roster membership key"));
        }
        if (!resolver.isConfigured()) {
            throw new IllegalStateException(refusal("identity.authority.publication.resolver-base-url is not "
                    + "set, so there is nowhere to publish a head to"));
        }
        verifyWindow(publication);
        // Decoded here, once, so a malformed key in the Secret fails the deployment that publishes rather
        // than every transition it runs. The signer parses lazily precisely so that a deployment with
        // publishing off is not affected by the same key.
        try {
            signer.verifySigningKey();
        } catch (RuntimeException ex) {
            throw new IllegalStateException(refusal("the roster membership signing key configured for "
                    + "homeserver '" + signer.homeserverId() + "' is not a readable Ed25519 private key"), ex);
        }
        log.info("Authority head publication enabled for homeserver {}", signer.homeserverId());
    }

    private void verifyWindow(PublicationProperties publication) {
        Duration validity = publication.getHeadValidity();
        if (validity.isZero() || validity.isNegative()) {
            throw new IllegalStateException(refusal("identity.authority.publication.head-validity is "
                    + validity + ", which is not a window a head could be issued for"));
        }
        if (validity.compareTo(AuthorityHeadRecordCodec.MAX_VALIDITY) > 0) {
            throw new IllegalStateException(refusal("identity.authority.publication.head-validity is "
                    + validity + " but a " + AuthorityHeadRecord.DOMAIN + " may not be valid for longer than "
                    + AuthorityHeadRecordCodec.MAX_VALIDITY.toDays() + " days, so every head this deployment "
                    + "signed would be refused by its own codec"));
        }
        Duration republish = publication.getRepublishAfter();
        if (republish.isZero() || republish.isNegative()) {
            throw new IllegalStateException(refusal("identity.authority.publication.republish-after is "
                    + republish + ", which would re-issue a head on every pass over the account and grow the "
                    + "transparency log once per read"));
        }
        Duration retry = publication.getRetryAfter();
        if (retry.isNegative()) {
            throw new IllegalStateException(refusal("identity.authority.publication.retry-after is " + retry
                    + ", which is not a wait"));
        }
        if (republish.compareTo(validity) >= 0) {
            throw new IllegalStateException(refusal("identity.authority.publication.republish-after is "
                    + republish + ", which is not shorter than head-validity of " + validity + ", so a "
                    + "published head would reach its expiry before it was ever re-issued"));
        }
    }

    private static String refusal(String reason) {
        return "Refusing to start: identity.authority.publication.enabled is on but " + reason + ".";
    }
}
