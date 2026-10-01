// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Scheduling is enabled only with the shadow comparison flag, so no scheduler starts while it is off. */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(prefix = "identity.placement.shadow", name = "enabled", havingValue = "true")
public class PlacementSchedulingConfig {
}
