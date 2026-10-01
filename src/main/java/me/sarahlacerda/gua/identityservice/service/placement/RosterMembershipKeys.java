// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * Holds each homeserver's roster membership key, which signs both placement records and authority heads.
 * Keys are parsed on first use so a malformed key cannot stop a deployment that publishes nothing.
 */
@Component
public class RosterMembershipKeys {

    private final Map<String, String> configured = new LinkedHashMap<>();

    private final Map<String, PrivateKey> loaded = new ConcurrentHashMap<>();

    @Autowired
    public RosterMembershipKeys(IdentityServiceProperties properties, FederationIds federationIds) {
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            String key = homeserver.getPlacementSigningPrivateKey();
            if (key == null || key.isBlank()) {
                continue;
            }
            configured.put(federationIds.of(homeserver), key);
        }
    }

    public RosterMembershipKeys(IdentityServiceProperties properties) {
        this(properties, new FederationIds(properties));
    }

    public boolean holdsKeyFor(String federationId) {
        return federationId != null && configured.containsKey(federationId);
    }

    public Set<String> federationIds() {
        return Collections.unmodifiableSet(configured.keySet());
    }

    public PrivateKey signingKey(String federationId) {
        String text = configured.get(federationId);
        if (text == null) {
            throw new IllegalStateException("No roster membership signing key is configured for homeserver "
                    + federationId);
        }
        return loaded.computeIfAbsent(federationId, id -> Ed25519Keys.privateKeyFromPkcs8(configured.get(id)));
    }
}
