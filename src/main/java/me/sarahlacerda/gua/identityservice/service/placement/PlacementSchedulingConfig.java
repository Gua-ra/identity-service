// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Turns Spring's scheduler on, and only for the shadow comparison.
 *
 * <p>Nothing in this application scheduled anything before this: the genesis expiry sweep runs on a
 * write path precisely so that no scheduler had to exist. Enabling scheduling unconditionally would
 * start a thread pool in every deployment for a feature almost none of them have turned on, and would
 * break the promise that with the flags off this service behaves exactly as it did before. Gating the
 * {@code @EnableScheduling} on the same flag as the job keeps that promise literally true:
 * {@code PlacementFlagsOffGuardTest} fails if this condition is removed or widened.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(prefix = "identity.placement.shadow", name = "enabled", havingValue = "true")
public class PlacementSchedulingConfig {
}
