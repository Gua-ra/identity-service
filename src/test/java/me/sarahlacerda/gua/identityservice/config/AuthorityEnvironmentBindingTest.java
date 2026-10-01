// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.config;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The variable names are set in another repository (gua-deploy). A misspelt one binds nothing and the property
 * keeps its default, so the names are pinned here.
 */
class AuthorityEnvironmentBindingTest {

    private static final Map<String, Object> BASE = Map.of(
            "IDENTITY_MATRIX_ADMIN_API_BASE_URL", "https://example.invalid",
            "IDENTITY_MATRIX_CLIENT_API_BASE_URL", "https://example.invalid",
            "IDENTITY_MATRIX_HOME_DOMAIN", "example.invalid",
            "IDENTITY_MATRIX_ADMIN_TOKEN", "unused-in-this-test",
            "IDENTITY_DIRECTORY_PEPPER", "unused-in-this-test",
            "IDENTITY_BASE_URL", "https://example.invalid");

    private static final Map<String, Object> DEV_AUTHORITY = Map.ofEntries(
            Map.entry("IDENTITY_AUTHORITY_ENABLED", "true"),
            Map.entry("IDENTITY_AUTHORITY_ADOPTION_PERMITTED", "true"),
            Map.entry("IDENTITY_AUTHORITY_NOTIFICATIONS_ENABLED", "true"),
            Map.entry("IDENTITY_AUTHORITY_OPPOSITION_WINDOW", "PT5M"),
            Map.entry("IDENTITY_AUTHORITY_RECOVERY_WINDOW", "PT10M"),
            Map.entry("IDENTITY_AUTHORITY_ALLOW_SHORT_WINDOWS_FOR_TESTING", "true"),
            Map.entry("IDENTITY_AUTHORITY_APNS_BASE_URL", "https://api.push.apple.com"),
            Map.entry("IDENTITY_AUTHORITY_APNS_KEY_ID", "AAAAAAAAAA"),
            Map.entry("IDENTITY_AUTHORITY_APNS_TEAM_ID", "BBBBBBBBBB"),
            Map.entry("IDENTITY_AUTHORITY_APNS_PRIVATE_KEY", "bm90LWEta2V5"),
            Map.entry("IDENTITY_AUTHORITY_NOTIFICATIONS_APNS_TOPICS_GLOBAL_GUA_DEV_IOS_PROD", "global.gua.dev"),
            Map.entry("IDENTITY_AUTHORITY_FCM_BASE_URL", "https://fcm.googleapis.com"),
            Map.entry("IDENTITY_AUTHORITY_FCM_PROJECT_ID", "gua-dev"),
            Map.entry("IDENTITY_AUTHORITY_FCM_CLIENT_EMAIL", "gua-identity-fcm@gua-dev.iam.gserviceaccount.com"),
            Map.entry("IDENTITY_AUTHORITY_FCM_PRIVATE_KEY", "bm90LWEta2V5"));

    @Test
    void theDevDeployBlockTurnsTheFeatureOnAndNothingElseDoes() throws IOException {
        IdentityServiceProperties.AuthorityProperties authority = bind(DEV_AUTHORITY).getAuthority();

        assertThat(authority.isEnabled()).isTrue();
        assertThat(authority.isAdoptionPermitted()).isTrue();
        assertThat(authority.getNotifications().isEnabled()).isTrue();
        assertThat(authority.getOppositionWindow()).hasMinutes(5);
        assertThat(authority.getRecoveryWindow()).hasMinutes(10);
        assertThat(authority.isAllowShortWindowsForTesting()).isTrue();
    }

    @Test
    void theApnsTopicMapBindsFromAnEnvironmentVariableNameToTheAppIdTheClientSends() throws IOException {
        IdentityServiceProperties.ApnsProperties apns =
                bind(DEV_AUTHORITY).getAuthority().getNotifications().getApns();

        // A map has no placeholder in application.yml: relaxed binding derives the key from the variable name.
        assertThat(apns.getTopics()).containsExactly(Map.entry("global.gua.dev.ios.prod", "global.gua.dev"));
        assertThat(apns.getBaseUrl()).isEqualTo("https://api.push.apple.com");
        assertThat(apns.getKeyId()).isEqualTo("AAAAAAAAAA");
        assertThat(apns.getTeamId()).isEqualTo("BBBBBBBBBB");
    }

    @Test
    void theIndexedFormAnOperatorWouldGuessDoesNotProduceAnAppIdKey() throws IOException {
        Map<String, Object> wrong = new LinkedHashMap<>(DEV_AUTHORITY);
        wrong.remove("IDENTITY_AUTHORITY_NOTIFICATIONS_APNS_TOPICS_GLOBAL_GUA_DEV_IOS_PROD");
        wrong.put("IDENTITY_AUTHORITY_APNS_TOPICS_0_APP_ID", "global.gua.dev.ios.prod");
        wrong.put("IDENTITY_AUTHORITY_APNS_TOPICS_0_TOPIC", "global.gua.dev");

        assertThat(bind(wrong).getAuthority().getNotifications().getApns().getTopics())
                .doesNotContainKey("global.gua.dev.ios.prod");
    }

    @Test
    void withNothingSetEveryAuthorityFlagIsOffAndNoTransportIsConfigured() throws IOException {
        IdentityServiceProperties.AuthorityProperties authority = bind(Map.of()).getAuthority();

        assertThat(authority.isEnabled()).isFalse();
        assertThat(authority.isAdoptionPermitted()).isFalse();
        assertThat(authority.getNotifications().isEnabled()).isFalse();
        assertThat(authority.getNotifications().getApns().getBaseUrl()).isEmpty();
        assertThat(authority.getNotifications().getApns().getTopics()).isEmpty();
        assertThat(authority.getNotifications().getFcm().getBaseUrl()).isEmpty();
        assertThat(authority.getOppositionWindow()).hasHours(72);
    }

    private static IdentityServiceProperties bind(Map<String, Object> variables) throws IOException {
        Map<String, Object> environment = new LinkedHashMap<>(BASE);
        environment.putAll(variables);

        StandardEnvironment context = new StandardEnvironment();
        context.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                        environment));
        List<PropertySource<?>> yaml =
                new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"));
        yaml.forEach(source -> context.getPropertySources().addLast(source));

        return Binder.get(context).bind("identity", IdentityServiceProperties.class).get();
    }
}
