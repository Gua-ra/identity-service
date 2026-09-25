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
 * The deployment contract: these exact environment variable names, and no others, turn the account
 * authority feature on.
 *
 * <p>This test exists because the names are written in a different repository. gua-deploy's
 * {@code k8s/scripts/deploy-env.sh} sets them on the dev deployment, and nothing in a compiler or in
 * this service's own tests would notice if a name there stopped matching a property here: a misspelt
 * variable binds nothing, the property keeps its default, and the service starts perfectly happily with
 * the feature off or, worse, on with an unmapped APNs topic. The first evidence would be an alert that
 * was never delivered, which is precisely the failure ADM-009 gate 2 exists to prevent.
 *
 * <p>The map of topics is the reason this is not paranoia. Every other value here is a placeholder in
 * {@code application.yml} that names its own variable, so it is at least greppable from one side. The
 * topics map has no placeholder, because a map cannot have one: it is bound by Spring's relaxed rules
 * straight off the environment, where {@code ..._TOPICS_GLOBAL_GUA_DEV_IOS_PROD} becomes the key
 * {@code global.gua.dev.ios.prod}. That rule is real but it is not obvious, and an operator's first
 * guess, an indexed pair of {@code _0_APP_ID} and {@code _0_TOPIC}, silently produces two junk keys and
 * an unmapped app id. So the rule is asserted rather than assumed.
 */
class AuthorityEnvironmentBindingTest {

    /** Values every deployment already sets, here only so placeholders elsewhere resolve. */
    private static final Map<String, Object> BASE = Map.of(
            "IDENTITY_MATRIX_ADMIN_API_BASE_URL", "https://example.invalid",
            "IDENTITY_MATRIX_CLIENT_API_BASE_URL", "https://example.invalid",
            "IDENTITY_MATRIX_HOME_DOMAIN", "example.invalid",
            "IDENTITY_MATRIX_ADMIN_TOKEN", "unused-in-this-test",
            "IDENTITY_DIRECTORY_PEPPER", "unused-in-this-test",
            "IDENTITY_BASE_URL", "https://example.invalid");

    /**
     * Exactly what gua-deploy's dev block sets, transcribed. A change on either side breaks this.
     */
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

        // The key is the app id AppSettings.pusherAppID sends from a release build of the QA app, and the
        // value is the bundle id, which is the APNs topic the dev signing key is restricted to.
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

        // Not a failure anyone would see at startup, which is the whole point: the app id is simply not
        // mapped, and AuthorityApnsTransport would then send to a topic that is the app id verbatim.
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

    /** Binds the real application.yml with the given variables in front of it, as Kubernetes would. */
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
