package me.sarahlacerda.gua.identityservice.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The wall clock, as a bean, so time-window logic can be tested at its exact boundaries instead
 * of around {@code Instant.now()}.
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
