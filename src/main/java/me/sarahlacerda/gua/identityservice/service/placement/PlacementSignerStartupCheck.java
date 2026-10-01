// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.security.PrivateKey;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient.RosterEntryView;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient.RosterView;

// Fails startup unless each publishing homeserver's ACTIVE roster entry matches the configured id and key.
// Inert unless identity.placement.publish.enabled is on.
@Component
public class PlacementSignerStartupCheck {

    private static final Logger log = LoggerFactory.getLogger(PlacementSignerStartupCheck.class);

    private final IdentityServiceProperties properties;
    private final ResolverPlacementClient resolver;
    private final PlacementRecordSigner signer;

    public PlacementSignerStartupCheck(IdentityServiceProperties properties, ResolverPlacementClient resolver,
            PlacementRecordSigner signer) {
        this.properties = properties;
        this.resolver = resolver;
        this.signer = signer;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void verifyPlacementSigningIdentity() {
        if (!properties.getPlacement().getPublish().isEnabled()) {
            return;
        }
        verifyValidityWindow();
        if (properties.getRouting().getHomeservers().isEmpty()) {
            throw new IllegalStateException("identity.placement.publish.enabled is on but no "
                    + "identity.routing.homeservers are configured. The legacy synthesised homeserver has no "
                    + "federation roster identity, so there is no roster id a placement record could name and "
                    + "no membership key to sign one with. Configure the homeservers explicitly, each with a "
                    + "federation-id and a placement signing key, or turn publishing off.");
        }
        if (!resolver.isConfigured()) {
            throw new IllegalStateException("identity.placement.publish.enabled is on but "
                    + "identity.placement.resolver-base-url is not set, so the roster this deployment's "
                    + "signing identity must agree with cannot be read.");
        }
        RosterView roster = resolver.fetchRoster().orElseThrow(() -> new IllegalStateException(
                "identity.placement.publish.enabled is on but the federation roster could not be read. "
                        + "Refusing to start rather than sign placement records under an unverified identity."));

        int verified = 0;
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            String configuredKey = homeserver.getPlacementSigningPrivateKey();
            if (configuredKey == null || configuredKey.isBlank()) {
                continue;
            }
            verifyOne(homeserver, roster);
            verified++;
        }

        if (verified == 0) {
            throw new IllegalStateException("identity.placement.publish.enabled is on but no configured "
                    + "homeserver carries a placement signing key, so no record could ever be signed.");
        }
        log.info("Placement signing identity verified against the roster for {} homeserver(s)", verified);
    }

    /** Checked at boot so a window the codec would refuse fails startup. */
    private void verifyValidityWindow() {
        Duration validity = properties.getPlacement().getRecordValidity();
        if (validity.isZero() || validity.isNegative()) {
            throw new IllegalStateException("Refusing to start: identity.placement.record-validity is "
                    + validity + ", which is not a window a record could be issued for.");
        }
        if (validity.compareTo(PlacementRecordCodec.MAX_VALIDITY) > 0) {
            throw new IllegalStateException("Refusing to start: identity.placement.record-validity is "
                    + validity + " but a placement record may not be valid for longer than "
                    + PlacementRecordCodec.MAX_VALIDITY.toDays() + " days (ADM-008 decision 7), so every "
                    + "record this deployment signed would be refused by its own codec.");
        }
        Duration reissue = properties.getPlacement().getReissueAfter();
        if (reissue.compareTo(validity) >= 0) {
            throw new IllegalStateException("Refusing to start: identity.placement.reissue-after is "
                    + reissue + ", which is not shorter than identity.placement.record-validity of "
                    + validity + ", so a record would reach its expiry before it was ever re-issued.");
        }
    }

    private void verifyOne(HomeserverConfig homeserver, RosterView roster) {
        String localId = homeserver.getId();
        String federationId = signer.federationIdOf(homeserver);

        // The join between the two namespaces is the Matrix domain, which is unique in the roster.
        RosterEntryView entry = roster.entries() == null ? null
                : roster.entries().stream()
                        .filter(candidate -> candidate.homeserver() != null
                                && homeserver.getDomain().equals(candidate.homeserver().serverName()))
                        .findFirst()
                        .orElse(null);
        if (entry == null) {
            throw new IllegalStateException(failure(localId, "its Matrix domain matches no federation roster "
                    + "entry, so the homeserver it would sign records for is not an admitted member"));
        }
        if (!entry.isActive()) {
            throw new IllegalStateException(failure(localId, "its roster entry is " + entry.status()
                    + " rather than ACTIVE, and a record signed by a member that is not active is refused"));
        }
        String rosterId = entry.homeserver().id();
        if (!federationId.equals(rosterId)) {
            throw new IllegalStateException(failure(localId, "the configured federation id '" + federationId
                    + "' is not the roster id '" + rosterId + "' of its entry. A record carries the roster id, "
                    + "so publishing would name the wrong homeserver"));
        }

        byte[] rosterKey = Ed25519Keys.rawPublicKeyFromBase64(entry.homeserver().signingKey(),
                "bad_roster_signing_key");
        PrivateKey privateKey = Ed25519Keys.privateKeyFromPkcs8(homeserver.getPlacementSigningPrivateKey());
        if (!Ed25519Keys.publicHalfMatches(privateKey, rosterKey)) {
            throw new IllegalStateException(failure(localId, "the configured placement signing key is not the "
                    + "private half of the key its roster entry publishes, so every record it signed would be "
                    + "rejected. If the roster entry was seeded with a public key nobody holds the private half "
                    + "of, re-admit the homeserver with a fresh pair"));
        }
    }

    /** Homeservers are named by their configured id, never by their domain or address. */
    private static String failure(String localId, String reason) {
        return "Refusing to start: placement publishing is enabled for homeserver '" + localId + "' but "
                + reason + ".";
    }
}
