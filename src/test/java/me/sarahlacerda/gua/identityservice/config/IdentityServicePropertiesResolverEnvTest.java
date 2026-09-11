package me.sarahlacerda.gua.identityservice.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/**
 * The deployed manifests still export {@code IDENTITY_RESOLVER_BASEURL},
 * {@code IDENTITY_RESOLVER_HOMESERVERID} and {@code IDENTITY_RESOLVER_SIGNINGPRIVATEKEY} until
 * the deployment repo drops them. Nothing maps those names any more (the resolver publishing
 * client and its properties are removed, ADM-001 L1b), and {@code @ConfigurationProperties}
 * ignores unknown keys by default, so startup must not care that they are set.
 *
 * <p>This pins that through the same binder the application uses, with the variables presented
 * the way the OS environment presents them.
 */
class IdentityServicePropertiesResolverEnvTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesOnly.class)
            .withPropertyValues(
                    "identity.matrix.admin-api-base-url=http://synapse:8008",
                    "identity.matrix.client-api-base-url=http://synapse:8008",
                    "identity.matrix.homeserver-domain=example.test",
                    "identity.matrix.admin-access-token=admin-token",
                    "identity.directory.pepper=pepper");

    @Test
    void staleResolverEnvironmentVariablesAreIgnored() {
        Map<String, Object> staleManifestEnv = Map.of(
                "IDENTITY_RESOLVER_BASEURL", "http://resolver.example.test",
                "IDENTITY_RESOLVER_HOMESERVERID", "hs-1",
                "IDENTITY_RESOLVER_SIGNINGPRIVATEKEY", "stale-key-material");

        runner.withInitializer(ctx -> ctx.getEnvironment().getPropertySources()
                        .addFirst(new SystemEnvironmentPropertySource("stale-manifest-env", staleManifestEnv)))
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    assertThat(ctx).hasSingleBean(IdentityServiceProperties.class);
                    // The variables really are visible to relaxed binding; there is just no
                    // identity.resolver.* property left for them to land on.
                    assertThat(ctx.getEnvironment().getProperty("identity.resolver.baseurl"))
                            .isEqualTo("http://resolver.example.test");
                    assertThat(ctx.getBean(IdentityServiceProperties.class).getDirectory().getPepper())
                            .isEqualTo("pepper");
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(IdentityServiceProperties.class)
    static class PropertiesOnly {
    }
}
