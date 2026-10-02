package me.sarahlacerda.gua.identityservice.service.placement;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Turns Spring's scheduler on, and only for the shadow comparison. Gating {@code @EnableScheduling}
 * on the same flag as the job means a deployment with the flag off starts no scheduler thread pool.
 * {@code PlacementFlagsOffGuardTest} fails if this condition is removed or widened.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(prefix = "identity.placement.shadow", name = "enabled", havingValue = "true")
public class PlacementSchedulingConfig {
}
