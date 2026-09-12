// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementAccountScanner;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementRecordSigner;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementSchedulingConfig;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementShadowMetrics;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementShadowReconciler;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementSignerStartupCheck;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Every new path is behind a flag that defaults to false, and with the flags off this service behaves
 * exactly as it did before placement records existed.
 *
 * <p>"Exactly as before" is meant literally, which is why the scheduler is part of this test. Nothing in
 * this application scheduled anything until now: the genesis expiry sweep runs on a write path precisely
 * so no scheduler had to exist. An unconditional {@code @EnableScheduling} would start a thread pool in
 * every deployment for a feature almost none of them have turned on, so the annotation is gated on the
 * same flag as the job it exists for.
 */
class PlacementFlagsOffGuardTest {

    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");

    private final IdentityServiceProperties untouched = new IdentityServiceProperties();

    @Test
    void everyPlacementFlagDefaultsToOff() {
        IdentityServiceProperties.PlacementProperties placement = untouched.getPlacement();

        assertThat(placement.getPublish().isEnabled()).isFalse();
        assertThat(placement.getShadow().isEnabled()).isFalse();
        assertThat(placement.getShadow().isHealDirectory()).isFalse();
        assertThat(placement.getMas().getAdminApi().isEnabled()).isFalse();
        assertThat(placement.getMas().getSql().isEnabled()).isFalse();
        assertThat(placement.getResolverBaseUrl()).isEmpty();
        assertThat(placement.getFederationIdAliases()).isEmpty();
        assertThat(placement.getShadow().getKnownPlacements()).isEmpty();
    }

    @Test
    void aHomeserverCarriesNoSigningKeyOrFederationIdUntilOneIsConfigured() {
        IdentityServiceProperties.HomeserverConfig homeserver =
                new IdentityServiceProperties.HomeserverConfig();

        assertThat(homeserver.getFederationId()).isNull();
        assertThat(homeserver.getPlacementSigningPrivateKey()).isNull();
        assertThat(homeserver.getMas().getAdminApiBaseUrl()).isEmpty();
        assertThat(homeserver.getMas().getReadOnlyJdbcUrl()).isEmpty();
    }

    @Test
    void theShippedConfigurationTurnsEveryPlacementFlagOff() throws IOException {
        String yaml = Files.readString(Path.of("src", "main", "resources", "application.yml"));

        assertThat(yaml).contains("IDENTITY_PLACEMENT_PUBLISH_ENABLED:false");
        assertThat(yaml).contains("IDENTITY_PLACEMENT_SHADOW_ENABLED:false");
        assertThat(yaml).contains("IDENTITY_PLACEMENT_SHADOW_HEAL_DIRECTORY:false");
        assertThat(yaml).contains("IDENTITY_PLACEMENT_MAS_ADMIN_API_ENABLED:false");
        assertThat(yaml).contains("IDENTITY_PLACEMENT_MAS_SQL_ENABLED:false");
        assertThat(yaml).contains("IDENTITY_PLACEMENT_RESOLVER_BASE_URL:}");
    }

    @Test
    void theSchedulerIsStartedOnlyWhenTheComparisonIsTurnedOn() {
        assertThat(PlacementSchedulingConfig.class.getAnnotation(EnableScheduling.class)).isNotNull();

        ConditionalOnProperty condition =
                PlacementSchedulingConfig.class.getAnnotation(ConditionalOnProperty.class);
        assertThat(condition).isNotNull();
        assertThat(condition.prefix()).isEqualTo("identity.placement.shadow");
        assertThat(condition.name()).containsExactly("enabled");
        assertThat(condition.havingValue()).isEqualTo("true");
        // Without this, a deployment that set nothing would still get a scheduler it never had before.
        assertThat(condition.matchIfMissing()).isFalse();
    }

    @Test
    void noOtherClassTurnsSchedulingOn() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            if (file.getFileName().toString().equals("PlacementSchedulingConfig.java")) {
                continue;
            }
            for (String line : codeLines(file)) {
                if (line.contains("@EnableScheduling")) {
                    offenders.add(file.getFileName().toString());
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void withTheFlagsOffTheReconcilerTouchesNothing() {
        PlacementAccountScanner scanner = mock(PlacementAccountScanner.class);
        ResolverPlacementClient resolver = mock(ResolverPlacementClient.class);
        PlacementShadowReconciler reconciler = new PlacementShadowReconciler(untouched, scanner, List.of(),
                resolver, new PlacementRecordSigner(untouched),
                new PlacementShadowMetrics(new SimpleMeterRegistry(), untouched));

        assertThat(reconciler.reconcile()).isEmpty();

        verifyNoInteractions(scanner);
        verifyNoInteractions(resolver);
    }

    @Test
    void withPublishingOffTheStartupCheckReadsNothing() {
        ResolverPlacementClient resolver = mock(ResolverPlacementClient.class);
        PlacementSignerStartupCheck check = new PlacementSignerStartupCheck(untouched, resolver,
                new PlacementRecordSigner(untouched));

        assertThatCode(check::verifyPlacementSigningIdentity).doesNotThrowAnyException();

        verifyNoInteractions(resolver);
    }

    @Test
    void withTheFlagsOffNoNewMetricSeriesExists() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        new PlacementShadowMetrics(registry, untouched);

        assertThat(registry.getMeters()).isEmpty();
    }

    @Test
    void withNoResolverConfiguredTheClientIsInertAndBuildsNoHttpClient() {
        ResolverPlacementClient client = new ResolverPlacementClient(
                org.springframework.web.reactive.function.client.WebClient.builder(), untouched);

        assertThat(client.isConfigured()).isFalse();
        assertThat(client.fetchRoster()).isEmpty();
        assertThat(client.findRecord("ga1anything")).isEmpty();
        assertThat(client.publish(null)).isEqualTo(ResolverPlacementClient.PublishOutcome.UNAVAILABLE);
    }

    @Test
    void withNoKeyConfiguredTheSignerLoadsNothing() {
        PlacementRecordSigner signer = new PlacementRecordSigner(untouched);

        assertThat(signer.canSignFor("anything")).isFalse();
    }

    @Test
    void aMalformedSigningKeyDoesNotStopADeploymentWithPlacementOffFromStarting() {
        IdentityServiceProperties off = new IdentityServiceProperties();
        IdentityServiceProperties.HomeserverConfig homeserver =
                new IdentityServiceProperties.HomeserverConfig();
        homeserver.setId("primary");
        homeserver.setDomain("example.test");
        homeserver.setFederationId("fed-primary");
        homeserver.setPlacementSigningPrivateKey("this is not a key");
        off.getRouting().getHomeservers().add(homeserver);

        // With every flag off nothing will ever sign, so a key this service cannot parse is inert and
        // must not be a reason to refuse to start. A deployment that does publish still has every key
        // decoded and checked against the roster by PlacementSignerStartupCheck before it serves.
        assertThatCode(() -> new PlacementRecordSigner(off)).doesNotThrowAnyException();
    }

    @Test
    void withTheFlagsOffACompletedRunRecordsNothingEither() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        PlacementShadowMetrics metrics = new PlacementShadowMetrics(registry, untouched);

        metrics.runCompleted(99, 1_757_000_000L);
        metrics.failed("error");

        // Every method is gated on the flag, not just the ones that touch a counter, so nothing starts
        // accumulating state that would leak the moment someone registered these gauges unconditionally.
        assertThat(registry.getMeters()).isEmpty();
    }

    private static List<Path> mainSources() throws IOException {
        assertThat(MAIN_SOURCES).as("run from the identity-service project directory").isDirectory();
        try (Stream<Path> paths = Files.walk(MAIN_SOURCES)) {
            return paths.filter(path -> path.toString().endsWith(".java")).toList();
        }
    }

    private static List<String> codeLines(Path file) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String raw : Files.readAllLines(file)) {
            String line = raw.replaceAll("\\s//.*$", "").trim();
            if (line.isEmpty() || line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) {
                continue;
            }
            lines.add(line);
        }
        return lines;
    }
}
