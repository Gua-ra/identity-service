package me.sarahlacerda.gua.identityservice.service.routing;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/**
 * Default placement policy. Supports three strategies (config
 * {@code identity.routing.strategy}):
 *
 * <ul>
 *   <li><b>single</b> (default): always the registry's default homeserver. This
 *       is the behaviour of an existing single-homeserver deployment.</li>
 *   <li><b>region</b>: first enabled homeserver whose region matches the context
 *       region hint; otherwise falls back to weighted selection.</li>
 *   <li><b>weighted</b>: random pick across enabled homeservers proportional to
 *       their configured weight (simple load spreading).</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class DefaultHomeserverRouter implements HomeserverRouter {

    private static final Logger log = LoggerFactory.getLogger(DefaultHomeserverRouter.class);

    private final HomeserverRegistry registry;
    private final IdentityServiceProperties properties;

    @Override
    public Homeserver selectForNewAccount(AccountPlacementContext context) {
        String strategy = properties.getRouting().getStrategy();
        List<Homeserver> candidates = registry.enabled();
        if (candidates.isEmpty()) {
            throw new IllegalStateException("No enabled homeserver available for placement");
        }
        if (candidates.size() == 1 || "single".equalsIgnoreCase(strategy)) {
            return registry.getDefault();
        }

        if ("region".equalsIgnoreCase(strategy) && context.region().isPresent()) {
            String region = context.region().get();
            Homeserver match = candidates.stream()
                    .filter(hs -> region.equalsIgnoreCase(hs.region()))
                    .findFirst()
                    .orElse(null);
            if (match != null) {
                return match;
            }
            log.debug("No homeserver for region '{}'; falling back to weighted placement", region);
        }

        return weightedPick(candidates);
    }

    private Homeserver weightedPick(List<Homeserver> candidates) {
        int totalWeight = candidates.stream().mapToInt(hs -> Math.max(0, hs.weight())).sum();
        if (totalWeight <= 0) {
            // All weights zero/negative: fall back to a uniform pick.
            return candidates.get(ThreadLocalRandom.current().nextInt(candidates.size()));
        }
        int target = ThreadLocalRandom.current().nextInt(totalWeight);
        int cumulative = 0;
        for (Homeserver hs : candidates) {
            cumulative += Math.max(0, hs.weight());
            if (target < cumulative) {
                return hs;
            }
        }
        return candidates.get(candidates.size() - 1);
    }
}
