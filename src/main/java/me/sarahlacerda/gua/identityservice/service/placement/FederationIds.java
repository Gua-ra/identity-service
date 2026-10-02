package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Optional;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * The one place a homeserver's federation roster id is worked out.
 *
 * <p>The local registry id is what this deployment calls a homeserver and what
 * {@code directory_entries.homeserver_id} holds; the roster id is federation state and is what a
 * placement record carries. The signer and every MAS reader must derive the mapping here, aliases
 * included: if they disagreed, the shadow comparison's lookup would miss silently.
 * {@code PlacementRecordsNotServedGuardTest} fails if a reader grows its own copy.
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
     * comparison only. A configured homeserver answers for itself; the alias map covers values that
     * match no configured homeserver (the legacy synthesised id, rows written before routing existed).
     * Publishing uses the MAS link, never this value.
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
