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

/**
 * Refuses to start a deployment that would publish placement records under the wrong identity.
 *
 * <p>A generation-1 record is trusted because it is signed by the roster membership key of the
 * homeserver it names, and the resolver verifies it against the key in that homeserver's ACTIVE roster
 * entry. So three things have to line up before this service signs anything: the roster entry has to
 * exist and be ACTIVE, the roster id this deployment is configured to write into records has to be that
 * entry's id, and the private key in the deployment Secret has to be the private half of that entry's
 * published key. Any of them being wrong produces records the resolver silently rejects, or worse,
 * records naming a homeserver this deployment is not.
 *
 * <p>Checked once at startup and failed fast, in the pattern the directory pepper pin already uses: a
 * misconfiguration that only shows up as a rejection rate on a nightly job is a misconfiguration nobody
 * notices for a week.
 *
 * <p>Two namespaces meet here, which is the trap this guards. The local registry id is what
 * {@code directory_entries.homeserver_id} holds; the roster id is what a record carries. They are joined
 * on the Matrix domain, which is unique in the roster. The legacy synthesised homeserver has no roster
 * identity at all, so publishing requires an explicit {@code identity.routing.homeservers} list rather
 * than silently inventing one; the alias map exists only so that comparisons can read legacy directory
 * values, never so that a record can be signed for a guessed homeserver.
 *
 * <p>Inert unless {@code identity.placement.publish.enabled} is on. A deployment that only runs the
 * comparison never reaches this check, and one that has turned the feature off entirely never reads the
 * roster at all.
 */
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
                // Not a homeserver this deployment publishes for. Records are only ever signed for the
                // homeservers whose membership key it actually holds.
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

    /**
     * The configured window has to be one the codec will actually encode.
     *
     * <p>{@code recordValidity} is a freely configurable {@code Duration} while ADM-008 decision 7 fixes
     * validity at 400 days and {@link PlacementRecordCodec} refuses anything longer. Without this check a
     * value of, say, {@code P401D} is accepted at boot and then throws on every single signature, which
     * surfaces at 03:20 as a job that failed rather than as the misconfiguration it is. Refusing here
     * costs a restart; the alternative costs a night of the 14-day exit window.
     */
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
