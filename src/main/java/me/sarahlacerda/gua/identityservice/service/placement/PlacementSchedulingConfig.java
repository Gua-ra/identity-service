package me.sarahlacerda.gua.identityservice.service.placement;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@ConditionalOnProperty(prefix = "identity.placement.shadow", name = "enabled", havingValue = "true")
public class PlacementSchedulingConfig {
}
