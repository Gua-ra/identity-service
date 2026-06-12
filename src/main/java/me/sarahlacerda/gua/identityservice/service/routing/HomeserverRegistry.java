package me.sarahlacerda.gua.identityservice.service.routing;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/**
 * Authoritative, in-memory registry of the homeservers the Gua federation can
 * place accounts on.
 *
 * <p>Back-compatible by design: when {@code identity.routing.homeservers} is not
 * configured, the registry synthesises a single homeserver from the legacy
 * {@code identity.matrix.*} properties (id {@value #LEGACY_ID}), so existing
 * single-homeserver deployments behave exactly as before.
 */
@Component
@RequiredArgsConstructor
public class HomeserverRegistry {

    public static final String LEGACY_ID = "default";

    private static final Logger log = LoggerFactory.getLogger(HomeserverRegistry.class);

    private final IdentityServiceProperties properties;

    /** Insertion-ordered so deterministic strategies are stable. */
    private final Map<String, Homeserver> byId = new LinkedHashMap<>();
    private String defaultHomeserverId;

    @PostConstruct
    public void init() {
        List<HomeserverConfig> configured = properties.getRouting().getHomeservers();
        if (configured.isEmpty()) {
            Homeserver legacy = synthesizeLegacyHomeserver();
            byId.put(legacy.id(), legacy);
            defaultHomeserverId = legacy.id();
            log.info("HomeserverRegistry: no routing.homeservers configured; using legacy single homeserver '{}' ({})",
                    legacy.id(), legacy.domain());
            return;
        }
        for (HomeserverConfig hc : configured) {
            Homeserver hs = new Homeserver(hc.getId(), hc.getDomain(), hc.getAdminApiBaseUrl(),
                    hc.getClientApiBaseUrl(), hc.getAdminAccessToken(), hc.getRegion(), hc.getWeight(), hc.isEnabled());
            if (byId.putIfAbsent(hs.id(), hs) != null) {
                throw new IllegalStateException("Duplicate homeserver id in routing config: " + hs.id());
            }
        }
        defaultHomeserverId = resolveDefaultId(configured);
        log.info("HomeserverRegistry: {} homeserver(s) registered; default '{}'", byId.size(), defaultHomeserverId);
    }

    private Homeserver synthesizeLegacyHomeserver() {
        IdentityServiceProperties.MatrixProperties m = properties.getMatrix();
        return new Homeserver(LEGACY_ID, m.getHomeserverDomain(), m.getAdminApiBaseUrl(), m.getClientApiBaseUrl(),
                m.getAdminAccessToken(), null, 1, true);
    }

    private String resolveDefaultId(List<HomeserverConfig> configured) {
        String configuredDefault = properties.getRouting().getDefaultHomeserverId();
        if (configuredDefault != null && !configuredDefault.isBlank()) {
            if (!byId.containsKey(configuredDefault)) {
                throw new IllegalStateException("routing.default-homeserver-id references unknown homeserver: "
                        + configuredDefault);
            }
            return configuredDefault;
        }
        // Fall back to the first enabled homeserver in declaration order.
        return configured.stream()
                .filter(HomeserverConfig::isEnabled)
                .map(HomeserverConfig::getId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No enabled homeserver configured"));
    }

    /** All registered homeservers in declaration order. */
    public List<Homeserver> all() {
        return List.copyOf(byId.values());
    }

    /** Homeservers eligible to receive new accounts. */
    public List<Homeserver> enabled() {
        return byId.values().stream().filter(Homeserver::enabled).toList();
    }

    public Optional<Homeserver> findById(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    public Homeserver requireById(String id) {
        return findById(id).orElseThrow(() -> new IllegalArgumentException("Unknown homeserver id: " + id));
    }

    /** The homeserver that hosts the given Matrix domain, if any is registered. */
    public Optional<Homeserver> findByDomain(String domain) {
        return byId.values().stream().filter(hs -> hs.domain().equals(domain)).findFirst();
    }

    public Homeserver getDefault() {
        return requireById(defaultHomeserverId);
    }
}
