package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Optional;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/** The signer and every reader must derive the roster id through this class, aliases included. */
@Component
public class FederationIds {

    private final IdentityServiceProperties properties;

    public FederationIds(IdentityServiceProperties properties) {
        this.properties = properties;
    }

    public String of(HomeserverConfig homeserver) {
        String explicit = homeserver.getFederationId();
        if (explicit != null && !explicit.isBlank()) {
            return explicit.trim();
        }
        return aliasOrSelf(homeserver.getId());
    }

    /** For comparison only. Publishing uses the MAS link, never this value. */
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
