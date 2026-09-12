// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecord;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementAccountScanner.AccountRow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The shadow comparison: what each account is classified as, what is published, and the two things the
 * job must never do.
 */
class PlacementShadowReconcilerTest {

    private static final String USER_ID = "@alice:example.test";
    private static final String OTHER_FEDERATION_ID = "fed-elsewhere";

    private final TestEd25519.Pair pair = PlacementTestFixtures.keyPair();
    private final String accountId = PlacementTestFixtures.genesisRootedId("alice").value();

    private IdentityServiceProperties properties;
    private PlacementAccountScanner scanner;
    private ResolverPlacementClient resolver;
    private SimpleMeterRegistry registry;
    private PlacementShadowMetrics metrics;
    private FakeMasLinkReader reader;
    private PlacementShadowReconciler reconciler;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        properties = PlacementTestFixtures.propertiesWithOneHomeserver(pair);
        properties.getPlacement().getShadow().setEnabled(true);

        scanner = mock(PlacementAccountScanner.class);
        resolver = mock(ResolverPlacementClient.class);
        when(resolver.isConfigured()).thenReturn(true);
        when(resolver.findRecord(anyString())).thenReturn(Optional.empty());
        registry = new SimpleMeterRegistry();
        metrics = new PlacementShadowMetrics(registry, properties);
        reader = new FakeMasLinkReader();

        reconciler = build();

        logs = new ListAppender<>();
        logs.start();
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(PlacementShadowReconciler.class))
                .addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger(PlacementShadowReconciler.class))
                .detachAppender(logs);
    }

    private PlacementShadowReconciler build() {
        return new PlacementShadowReconciler(properties, scanner, List.of(reader), resolver,
                new PlacementRecordSigner(properties), metrics);
    }

    /** One account in the scan, with the given local routing choice. */
    private void account(String userId, String directoryHomeserverId) {
        account(userId, directoryHomeserverId, "GENESIS", accountId);
    }

    private void account(String userId, String directoryHomeserverId, String origin, String id) {
        when(scanner.nextBatch(anyString(), anyInt()))
                .thenReturn(List.of(new AccountRow(id, userId, origin, directoryHomeserverId)), List.of());
    }

    private PlacementRecord publishedRecord(String homeserverId, Instant issuedAt) {
        return PlacementRecordCodec.decode(PlacementRecordCodec.encode(AccountId.parse(accountId),
                AccountId.CLASS_GENESIS, homeserverId, issuedAt, issuedAt,
                issuedAt.plus(400, ChronoUnit.DAYS)));
    }

    private Map<PlacementShadowResult, Integer> run() {
        return reconciler.reconcile();
    }

    private List<String> messagesAt(Level level) {
        return logs.list.stream()
                .filter(event -> event.getLevel() == level)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    private String allLogText() {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage)
                .reduce("", (a, b) -> a + "\n" + b);
    }

    // --- The feature being off ------------------------------------------------

    @Test
    void withTheFlagOffNothingIsScannedReadOrPublished() {
        properties.getPlacement().getShadow().setEnabled(false);

        assertThat(build().reconcile()).isEmpty();

        verifyNoInteractions(scanner);
        verify(resolver, never()).findRecord(anyString());
        verify(resolver, never()).publish(any());
    }

    // --- The access this deployment has not been granted ----------------------

    @Test
    void withNoMasReadPathTheJobRefusesToRunAndSaysExactlyWhatToGrant() {
        reader.configured = false;

        assertThat(run()).isEmpty();

        // Reporting every account as unlinked would look like a finding rather than missing access.
        verifyNoInteractions(scanner);
        String refusal = String.join("\n", messagesAt(Level.ERROR));
        assertThat(refusal).contains("urn:mas:admin");
        assertThat(refusal).contains("admin_clients");
        assertThat(refusal).contains("read-only");
        assertThat(refusal).contains("upstream_oauth_links");
    }

    @Test
    void withNoResolverConfiguredTheJobRefusesToRun() {
        when(resolver.isConfigured()).thenReturn(false);

        assertThat(run()).isEmpty();

        verifyNoInteractions(scanner);
        assertThat(String.join("\n", messagesAt(Level.ERROR))).contains("resolver-base-url");
    }

    // --- The closed classification vocabulary ---------------------------------

    @Test
    void oneHomeAnAgreeingDirectoryAndAnAgreeingRecordIsAgree() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.findRecord(accountId))
                .thenReturn(Optional.of(publishedRecord(PlacementTestFixtures.FEDERATION_ID, Instant.now())));

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.AGREE, 1));
        // An agreeing account produces no structured line at all.
        assertThat(allLogText()).doesNotContain("placement_shadow");
    }

    @Test
    void oneHomeAnAgreeingDirectoryAndNoRecordIsRecordMissing() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.RECORD_MISSING, 1));
    }

    @Test
    void aLocalRoutingChoiceThatDisagreesIsDirectoryStale() {
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.DIRECTORY_STALE, 1));
        // A data-quality finding, not a correctness event: warned, not alerted.
        assertThat(messagesAt(Level.WARN)).anyMatch(line -> line.contains("result=directory_stale"));
        assertThat(messagesAt(Level.ERROR)).isEmpty();
    }

    @Test
    void aNullLocalRoutingChoiceIsReadThroughTheAliasMap() {
        properties.getPlacement().getFederationIdAliases().put("default", PlacementTestFixtures.FEDERATION_ID);
        reconciler = build();
        account(USER_ID, null);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        // A row written before routing existed means the legacy homeserver, and the alias says which
        // roster id that was; without it every legacy row would read as stale.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.RECORD_MISSING, 1));
    }

    @Test
    void noMasLinkAtAllIsMasNone() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.MAS_NONE, 1));
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("result=mas_none"));
    }

    @Test
    void linksOnTwoHomeserversIsMasMultiple() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        reader.link(USER_ID, OTHER_FEDERATION_ID, "alice");

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.MAS_MULTIPLE, 1));
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("reason=multiple_links"));
    }

    @Test
    void anAccountWhoseOwnIdNamesAnotherHomeserverIsMasMultiple() {
        String elsewhere = "@alice:somewhere.example.test";
        account(elsewhere, PlacementTestFixtures.LOCAL_ID);
        reader.link(elsewhere, PlacementTestFixtures.FEDERATION_ID, "alice");

        // One subject, two homeservers: its link says one place and its own id says another.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.MAS_MULTIPLE, 1));
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("reason=subject_home_mismatch"));
    }

    @Test
    void aMasUsernameThatIsNotTheAccountsOwnLocalpartIsMasUsernameMismatch() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "somebody-else");

        // Evidence of a merge onto a pre-existing MAS user through on_conflict: add.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.MAS_USERNAME_MISMATCH, 1));
    }

    @Test
    void aPublishedRecordNamingAnotherHomeserverIsRecordDisagrees() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.findRecord(accountId))
                .thenReturn(Optional.of(publishedRecord(OTHER_FEDERATION_ID, Instant.now())));

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.RECORD_DISAGREES, 1));
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("result=record_disagrees"));
    }

    @Test
    void everyAccountLandsInExactlyOneResult() {
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        Map<PlacementShadowResult, Integer> counts = run();

        assertThat(counts.values().stream().mapToInt(Integer::intValue).sum()).isEqualTo(1);
    }

    @Test
    void aKnownTestbedPlacementIsStillStaleButNotAlertedOn() {
        properties.getPlacement().getShadow().getKnownPlacements()
                .put(USER_ID, PlacementTestFixtures.FEDERATION_ID);
        reconciler = build();
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        // It stays in the bucket, so the exit criterion can read "none except the listed ones", but it
        // does not raise noise every night.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.DIRECTORY_STALE, 1));
        assertThat(messagesAt(Level.INFO)).anyMatch(line -> line.contains("known=true"));
        assertThat(messagesAt(Level.WARN)).noneMatch(line -> line.contains("result=directory_stale"));
    }

    // --- Publishing -----------------------------------------------------------

    @Test
    void withPublishingOffNoRecordIsEverSigned() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        run();

        verify(resolver, never()).publish(any());
    }

    @Test
    void withPublishingOnAMissingRecordIsSignedForTheHomeserverTheEvidenceNames() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.publish(any())).thenReturn(ResolverPlacementClient.PublishOutcome.PUBLISHED);

        run();

        ArgumentCaptor<PlacementRecordSigner.SignedPlacementRecord> captor =
                ArgumentCaptor.forClass(PlacementRecordSigner.SignedPlacementRecord.class);
        verify(resolver, times(1)).publish(captor.capture());
        PlacementRecord signed = PlacementRecordCodec.decode(
                Base64.getUrlDecoder().decode(captor.getValue().recordB64()));
        assertThat(signed.homeserverId()).isEqualTo(PlacementTestFixtures.FEDERATION_ID);
        assertThat(signed.accountId().value()).isEqualTo(accountId);
        assertThat(signed.generation()).isEqualTo(PlacementRecord.GENERATION_ONE);
    }

    @Test
    void aStaleDirectoryRowDoesNotStopAnOtherwiseCleanAccountBeingPublished() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.publish(any())).thenReturn(ResolverPlacementClient.PublishOutcome.PUBLISHED);

        // Publishing follows the evidence, not this service's local routing choice.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.DIRECTORY_STALE, 1));
        verify(resolver, times(1)).publish(any());
    }

    @Test
    void noRecordIsPublishedForAnyCorrectnessEvent() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        reader.link(USER_ID, OTHER_FEDERATION_ID, "alice");

        run();

        // A duplicate account is not something to assert a home for.
        verify(resolver, never()).publish(any());
    }

    @Test
    void aConflictIsCountedAndNeverRetriedOrForced() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.publish(any())).thenReturn(ResolverPlacementClient.PublishOutcome.CONFLICT);

        run();

        // One accountId has one home: the second homeserver is refused, not merged, and not retried.
        verify(resolver, times(1)).publish(any());
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("placement_conflict"));
    }

    @Test
    void noRecordIsSignedForAHomeserverThisDeploymentHoldsNoKeyFor() {
        // The other homeserver is configured, so the comparison resolves it, but carries no membership
        // key: this deployment is not the party entitled to assert where the account lives. It has to be
        // configured for this test to mean what its name says, because an unconfigured homeserver is a
        // different branch now and would pass this assertion for the wrong reason.
        String otherDomain = "other.example.test";
        String otherUser = "@alice:" + otherDomain;
        properties.getRouting().getHomeservers().add(PlacementTestFixtures.homeserver("other", otherDomain,
                OTHER_FEDERATION_ID, ""));
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(otherUser, PlacementTestFixtures.LOCAL_ID);
        reader.link(otherUser, OTHER_FEDERATION_ID, null);

        run();

        verify(resolver, never()).publish(any());
        assertThat(registry.counter("gua.identity.placement.publish", "result", "no_signing_key").count())
                .isEqualTo(1d);
    }

    @Test
    void aStoredOriginThatDisagreesWithTheAccountIdClassIsRefused() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        // A genesis-rooted id whose row claims BOOTSTRAP: the audit marker and the class byte must agree.
        account(USER_ID, PlacementTestFixtures.LOCAL_ID, "BOOTSTRAP", accountId);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        run();

        verify(resolver, never()).publish(any());
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("origin_class_mismatch"));
    }

    @Test
    void aRecordOlderThanTheReissueWindowIsReissued() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.findRecord(accountId)).thenReturn(Optional.of(publishedRecord(
                PlacementTestFixtures.FEDERATION_ID, Instant.now().minus(301, ChronoUnit.DAYS))));
        when(resolver.publish(any())).thenReturn(ResolverPlacementClient.PublishOutcome.PUBLISHED);

        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.AGREE, 1));
        verify(resolver, times(1)).publish(any());
    }

    @Test
    void aFreshRecordIsNotReissuedEveryNight() {
        properties.getPlacement().getPublish().setEnabled(true);
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        when(resolver.findRecord(accountId)).thenReturn(Optional.of(publishedRecord(
                PlacementTestFixtures.FEDERATION_ID, Instant.now().minus(10, ChronoUnit.DAYS))));

        run();

        verify(resolver, never()).publish(any());
    }

    // --- Healing --------------------------------------------------------------

    @Test
    void healingIsOffByDefault() {
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        run();

        verify(scanner, never()).healDirectoryHomeserver(anyString(), anyString());
    }

    @Test
    void healingTakesItsValueFromTheMasLinkAndNeverFromAPublishedRecord() {
        properties.getPlacement().getShadow().setHealDirectory(true);
        reconciler = build();
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");
        // A record exists and agrees; the heal still reads the evidence, and writes the LOCAL registry
        // id, because the directory column has always held that namespace.
        when(resolver.findRecord(accountId))
                .thenReturn(Optional.of(publishedRecord(PlacementTestFixtures.FEDERATION_ID, Instant.now())));

        run();

        verify(scanner).healDirectoryHomeserver(USER_ID, PlacementTestFixtures.LOCAL_ID);
    }

    @Test
    void aKnownPlacementIsNotHealedAway() {
        properties.getPlacement().getShadow().setHealDirectory(true);
        properties.getPlacement().getShadow().getKnownPlacements()
                .put(USER_ID, PlacementTestFixtures.FEDERATION_ID);
        reconciler = build();
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        run();

        verify(scanner, never()).healDirectoryHomeserver(anyString(), anyString());
    }

    // --- The two things this must never do ------------------------------------

    @Test
    void noPhoneNumberEverReachesTheLogs() {
        String phone = "+15550001111";
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "somebody-else");

        run();

        String text = allLogText();
        assertThat(text).doesNotContain(phone);
        assertThat(text).doesNotContain("5550001111");
        assertThat(text.toLowerCase(Locale.ROOT)).doesNotContain("phone");
        // It logged something, so the assertion above is not passing vacuously.
        assertThat(text).contains("placement_shadow");
    }

    @Test
    void theRowTheComparisonWalksCarriesNoPhoneAtAll() {
        List<String> components = Arrays.stream(AccountRow.class.getRecordComponents())
                .map(RecordComponent::getName)
                .toList();

        // The scan cannot log a phone it never selected.
        assertThat(components).containsExactly("accountId", "userId", "origin", "directoryHomeserverId");
        assertThat(components).noneMatch(name -> name.toLowerCase(Locale.ROOT).contains("phone"));
        assertThat(components).noneMatch(name -> name.toLowerCase(Locale.ROOT).contains("digest"));
    }

    @Test
    void aStructuredLineIsEmittedForEveryAccountThatDoesNotAgree() {
        account(USER_ID, "some-other-local-id");
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        run();

        String line = messagesAt(Level.WARN).stream()
                .filter(message -> message.startsWith("placement_shadow"))
                .findFirst()
                .orElseThrow();
        assertThat(line).contains("result=directory_stale");
        assertThat(line).contains("accountId=" + accountId);
        assertThat(line).contains("userId=" + USER_ID);
        assertThat(line).contains("masHomeserver=" + PlacementTestFixtures.FEDERATION_ID);
    }


    // --- Resolving a homeserver, and failing when it cannot be resolved -------

    @Test
    void aHomeserverWithNoExplicitFederationIdIsTheSameRosterIdToTheReaderAndToTheComparison() {
        // No explicit federationId, so the roster id comes from the alias map. This is the shape where
        // the mapping used to be computed two different ways: the readers ignored the alias map and
        // returned the local id while the comparison indexed by the aliased one, so the lookup missed,
        // both cross-checks were skipped, and the account was reported as a benign directory_stale.
        properties = new IdentityServiceProperties();
        properties.getPlacement().setResolverBaseUrl("http://resolver.invalid");
        properties.getPlacement().getShadow().setEnabled(true);
        properties.getPlacement().getFederationIdAliases()
                .put(PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.FEDERATION_ID);
        properties.getRouting().getHomeservers().add(PlacementTestFixtures.homeserverWithoutFederationId(
                PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.pkcs8(pair)));
        registry = new SimpleMeterRegistry();
        metrics = new PlacementShadowMetrics(registry, properties);
        reconciler = build();

        // The id a real reader reports, resolved through the one shared implementation it now uses.
        String readerId = new FederationIds(properties)
                .of(properties.getRouting().getHomeservers().get(0));
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, readerId, "somebody-else");

        // The real finding, not the misreport: a MAS username that is not this account's own localpart.
        assertThat(run()).containsExactly(Map.entry(PlacementShadowResult.MAS_USERNAME_MISMATCH, 1));
    }

    @Test
    void aHomeserverTheComparisonCannotResolveIsAFailureAndNeverAClassification() {
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, "fed-not-configured", "alice");

        Map<PlacementShadowResult, Integer> counts = run();

        // Both cross-checks need this homeserver's domain. Skipping them used to leave the account with
        // a clean result, which is a fail-open in exactly the counts the phase exit is read from.
        assertThat(counts).isEmpty();
        assertThat(registry.counter("gua.identity.placement.shadow.failures", "reason",
                "unknown_homeserver").count()).isEqualTo(1d);
        assertThat(messagesAt(Level.ERROR)).anyMatch(line -> line.contains("placement_shadow_failed")
                && line.contains("reason=unknown_homeserver"));
    }

    // --- One bad account does not end the run ---------------------------------

    @Test
    void oneUnreadableAccountIsCountedAndTheRunCarriesOn() {
        String poison = "@poison:example.test";
        when(scanner.nextBatch(anyString(), anyInt())).thenReturn(
                List.of(new AccountRow(accountId, poison, "GENESIS", PlacementTestFixtures.LOCAL_ID),
                        new AccountRow(accountId, USER_ID, "GENESIS", PlacementTestFixtures.LOCAL_ID)),
                List.of());
        reader.failFor(poison);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        Map<PlacementShadowResult, Integer> counts = run();

        // The scan used to die on the first such row, which stopped the success timestamp advancing and
        // read as "the job is not running" rather than "this account could not be compared".
        assertThat(counts).containsExactly(Map.entry(PlacementShadowResult.RECORD_MISSING, 1));
        assertThat(registry.counter("gua.identity.placement.shadow.failures", "reason", "error").count())
                .isEqualTo(1d);
        assertThat(messagesAt(Level.INFO)).anyMatch(line -> line.contains("comparison complete"));
    }

    @Test
    void aValidityWindowTheCodecRefusesFailsAccountsRatherThanTheWholeRun() {
        properties.getPlacement().getPublish().setEnabled(true);
        // A misconfiguration the property allows and the codec refuses. It is rejected at boot when
        // publishing is on; this is the backstop for every other way signing can throw.
        properties.getPlacement().setRecordValidity(Duration.ofDays(401));
        reconciler = build();
        account(USER_ID, PlacementTestFixtures.LOCAL_ID);
        reader.link(USER_ID, PlacementTestFixtures.FEDERATION_ID, "alice");

        Map<PlacementShadowResult, Integer> counts = run();

        assertThat(counts).isEmpty();
        verify(resolver, never()).publish(any());
        assertThat(registry.counter("gua.identity.placement.shadow.failures", "reason", "error").count())
                .isEqualTo(1d);
        assertThat(messagesAt(Level.INFO)).anyMatch(line -> line.contains("comparison complete"));
    }

    @Test
    void aFailedAccountIsNotCountedAsAnyResult() {
        String poison = "@poison:example.test";
        when(scanner.nextBatch(anyString(), anyInt())).thenReturn(
                List.of(new AccountRow(accountId, poison, "GENESIS", PlacementTestFixtures.LOCAL_ID)),
                List.of());
        reader.failFor(poison);

        Map<PlacementShadowResult, Integer> counts = run();

        // In particular not as agree: a comparison that did not happen is not agreement.
        assertThat(counts.values().stream().mapToInt(Integer::intValue).sum()).isZero();
        for (PlacementShadowResult result : PlacementShadowResult.values()) {
            assertThat(registry.counter("gua.identity.placement.shadow", "result", result.tag()).count())
                    .isZero();
        }
    }

    /** A reader that answers from memory, so no MAS and no credential is involved. */
    private static final class FakeMasLinkReader implements MasLinkReader {

        private final Map<String, List<MasLink>> links = new HashMap<>();
        private final Set<String> failing = new HashSet<>();
        private boolean configured = true;
        private Map<String, String> onConflict = Map.of();

        void link(String subject, String federationId, String masUsername) {
            links.computeIfAbsent(subject, key -> new ArrayList<>())
                    .add(new MasLink(federationId, subject, "mas-user", masUsername));
        }

        @Override
        public boolean isConfigured() {
            return configured;
        }

        @Override
        public String describe() {
            return "in-memory test reader";
        }

        /** Makes this one account unreadable, standing in for any reader that throws mid-scan. */
        void failFor(String subject) {
            failing.add(subject);
        }

        @Override
        public List<MasLink> linksFor(String subject) {
            if (failing.contains(subject)) {
                throw new IllegalStateException("the reader could not answer for this account");
            }
            return links.getOrDefault(subject, List.of());
        }

        @Override
        public Map<String, String> localpartOnConflictByHomeserver() {
            return onConflict;
        }
    }
}
