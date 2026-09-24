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
 * The one place a homeserver's roster membership signing key is held and parsed.
 *
 * <p>Two features sign with this key: a generation-1 placement record (ADM-008 decision 7) and a published
 * authority chain head (ADM-009 decision 12). Both are a homeserver's standing assertion about one account,
 * both are verified by the resolver against the key in that homeserver's ACTIVE roster entry, and both are
 * therefore the same key. It is configured once, as
 * {@code identity.routing.homeservers[].placement-signing-key}, and the name is left alone: renaming a
 * configured secret to suit a second reader breaks every deployment holding it.
 *
 * <p>Kept in one collaborator for the reason {@link FederationIds} gives about its own mapping. The same
 * logic in two signers is the same drift: one of them consults the alias map, the other does not, and the
 * two disagree about which key belongs to which roster id without either failing loudly.
 *
 * <h2>Keys are parsed on first use, not at construction</h2>
 *
 * <p>This bean is built in every deployment, including the overwhelming majority that publish nothing.
 * Parsing eagerly would mean a deployment holding a malformed key in its Secret failed to start even with
 * every flag off, which is the behaviour change the flags exist to prevent. The material is held as
 * configured text and decoded the first time something actually signs. A deployment that does publish has
 * every key decoded and checked before it serves anything: {@link PlacementSignerStartupCheck} for the
 * placement path and {@code AuthorityPublicationStartupCheck} for the head path.
 */
@Component
public class RosterMembershipKeys {

    /** Federation roster id to the configured base64 PKCS#8 text of that homeserver's membership key. */
    private final Map<String, String> configured = new LinkedHashMap<>();

    /** The decoded halves, populated on first use. */
    private final Map<String, PrivateKey> loaded = new ConcurrentHashMap<>();

    @Autowired
    public RosterMembershipKeys(IdentityServiceProperties properties, FederationIds federationIds) {
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            String key = homeserver.getPlacementSigningPrivateKey();
            if (key == null || key.isBlank()) {
                // A homeserver this deployment does not publish for.
                continue;
            }
            configured.put(federationIds.of(homeserver), key);
        }
    }

    /** For callers that build this directly rather than through the container. */
    public RosterMembershipKeys(IdentityServiceProperties properties) {
        this(properties, new FederationIds(properties));
    }

    /** True when this deployment holds the membership key of that roster homeserver. */
    public boolean holdsKeyFor(String federationId) {
        return federationId != null && configured.containsKey(federationId);
    }

    /** The roster ids this deployment can sign for, in configuration order. */
    public Set<String> federationIds() {
        return Collections.unmodifiableSet(configured.keySet());
    }

    /**
     * The decoded private half, parsed on first use.
     *
     * @throws IllegalStateException when no key is configured for that homeserver, which is a deployment
     *                              error rather than a per-account one
     */
    public PrivateKey signingKey(String federationId) {
        String text = configured.get(federationId);
        if (text == null) {
            throw new IllegalStateException("No roster membership signing key is configured for homeserver "
                    + federationId);
        }
        return loaded.computeIfAbsent(federationId, id -> Ed25519Keys.privateKeyFromPkcs8(configured.get(id)));
    }
}
