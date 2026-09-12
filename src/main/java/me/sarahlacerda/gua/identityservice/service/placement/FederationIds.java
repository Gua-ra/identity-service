// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Optional;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * The one place a homeserver's federation roster id is worked out.
 *
 * <p>Two namespaces meet in the shadow comparison. The local registry id is what this deployment calls a
 * homeserver and what {@code directory_entries.homeserver_id} holds; the roster id is federation state and
 * is what a placement record carries. Every part of the comparison has to agree on that mapping, because
 * the job indexes the configured homeservers by roster id and then looks up the roster id a MAS reader
 * returned. If the two sides computed it differently the lookup would miss, and a missed lookup is not a
 * loud failure: it silently skips the cross-checks and reports the account as a benign data-quality
 * finding instead of the correctness event it is.
 *
 * <p>That is exactly what happened while this logic existed three times over. The signer consulted
 * {@code identity.placement.federation-id-aliases} and the two MAS readers did not, so a homeserver with
 * no explicit {@code federationId} but an alias for its local id was one id to the signer and another to
 * the reader. Keeping the rule in one collaborator is what makes that class of bug unrepresentable, and
 * {@code PlacementRecordsNotServedGuardTest} fails if a reader grows its own copy again.
 */
@Component
public class FederationIds {

    private final IdentityServiceProperties properties;

    public FederationIds(IdentityServiceProperties properties) {
        this.properties = properties;
    }

    /**
     * The roster id a configured homeserver publishes under: its explicit {@code federationId}, else the
     * alias configured for its local registry id, else the local id itself.
     */
    public String of(HomeserverConfig homeserver) {
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
     * <p>A configured homeserver answers for itself, which is the ordinary case. The alias map is for the
     * values that match no configured homeserver, which in practice means the legacy synthesised id and
     * the rows written before routing existed. Getting this wrong produces false stale-directory findings
     * and nothing worse, because publishing uses the MAS link and never this value.
     */
    public String forRegistryId(String registryId) {
        if (registryId == null || registryId.isBlank()) {
            return null;
        }
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            if (registryId.equals(homeserver.getId())) {
                return of(homeserver);
            }
        }
        return aliasOrSelf(registryId);
    }

    private String aliasOrSelf(String registryId) {
        return Optional.ofNullable(properties.getPlacement().getFederationIdAliases().get(registryId))
                .filter(alias -> !alias.isBlank())
                .orElse(registryId);
    }
}
