// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.time.Instant;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecord;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.ShadowProperties;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;

// Shadow mode: compute, publish, compare, serve nothing.
// It never logs or reads a phone number, and nothing here feeds the resolution path.
@Component
public class PlacementShadowReconciler {

    private static final Logger log = LoggerFactory.getLogger(PlacementShadowReconciler.class);

    static final String NO_MAS_ACCESS = """
            Placement shadow reconciliation is enabled but this deployment has no way to read the MAS \
            links that are the only committed evidence of where an account lives, so the comparison did \
            not run. Exactly one of these has to be granted first. \
            (1) The admin API path: set identity.placement.mas.admin-api.enabled and give each \
            homeserver's MAS client the urn:mas:admin scope through client_credentials, which MAS grants \
            only to a client id listed in its authorization policy data admin_clients. \
            (2) The SQL fallback: set identity.placement.mas.sql.enabled and create a read-only login \
            role on each MAS database with SELECT on upstream_oauth_links, users and \
            upstream_oauth_providers, and on nothing else. \
            Reporting every account as having no MAS link would look like a finding rather than like \
            missing access, so nothing is counted and no record is published.""";

    private final IdentityServiceProperties properties;
    private final PlacementAccountScanner scanner;
    private final List<MasLinkReader> readers;
    private final ResolverPlacementClient resolver;
    private final PlacementRecordSigner signer;
    private final PlacementShadowMetrics metrics;

    public PlacementShadowReconciler(IdentityServiceProperties properties, PlacementAccountScanner scanner,
            List<MasLinkReader> readers, ResolverPlacementClient resolver, PlacementRecordSigner signer,
            PlacementShadowMetrics metrics) {
        this.properties = properties;
        this.scanner = scanner;
        this.readers = readers;
        this.resolver = resolver;
        this.signer = signer;
        this.metrics = metrics;
    }

    @Scheduled(cron = "${identity.placement.shadow.cron:0 20 3 * * *}")
    public void reconcileOnSchedule() {
        reconcile();
    }

    /** Returns an empty map when the job refused to run. */
    public Map<PlacementShadowResult, Integer> reconcile() {
        ShadowProperties shadow = properties.getPlacement().getShadow();
        if (!shadow.isEnabled()) {
            return Map.of();
        }
        MasLinkReader reader = configuredReader();
        if (reader == null) {
            log.error(NO_MAS_ACCESS);
            return Map.of();
        }
        if (!resolver.isConfigured()) {
            log.error("Placement shadow reconciliation is enabled but identity.placement.resolver-base-url "
                    + "is not set, so published records cannot be read back to compare against.");
            return Map.of();
        }

        Map<String, HomeserverConfig> byFederationId = indexByFederationId();
        EnumMap<PlacementShadowResult, Integer> counts = new EnumMap<>(PlacementShadowResult.class);
        Instant now = Instant.now();
        long scanned = 0;
        long failures = 0;
        String cursor = "";

        while (true) {
            List<PlacementAccountScanner.AccountRow> batch = scanner.nextBatch(cursor, shadow.getBatchSize());
            if (batch.isEmpty()) {
                break;
            }
            for (PlacementAccountScanner.AccountRow row : batch) {
                scanned++;
                PlacementShadowResult result;
                try {
                    result = examine(row, reader, byFederationId, shadow, now);
                } catch (UnknownHomeserverException ex) {
                    // An unresolvable homeserver counts as a failure, never as agreement.
                    failures++;
                    metrics.failed("unknown_homeserver");
                    log.error("placement_shadow_failed accountId={} userId={} reason=unknown_homeserver "
                            + "masHomeserver={}", row.accountId(), row.userId(), ex.homeserverId());
                    continue;
                } catch (RuntimeException ex) {
                    // One unreadable row must not end the run.
                    failures++;
                    metrics.failed("error");
                    log.error("placement_shadow_failed accountId={} userId={} reason=error type={}",
                            row.accountId(), row.userId(), ex.getClass().getSimpleName(), ex);
                    continue;
                }
                counts.merge(result, 1, Integer::sum);
                metrics.classified(result);
            }
            cursor = batch.get(batch.size() - 1).userId();
        }

        metrics.localpartOnConflict(reader.localpartOnConflictByHomeserver());
        metrics.runCompleted(scanned, now.getEpochSecond());
        log.info("Placement shadow comparison complete: scanned={} failures={} results={} readPath={}",
                scanned, failures, counts, reader.describe());
        return counts;
    }

    private PlacementShadowResult examine(PlacementAccountScanner.AccountRow row, MasLinkReader reader,
            Map<String, HomeserverConfig> byFederationId, ShadowProperties shadow, Instant now) {

        List<MasLink> links = reader.linksFor(row.userId());
        Set<String> homes = new LinkedHashSet<>();
        for (MasLink link : links) {
            homes.add(link.federationId());
        }

        if (homes.isEmpty()) {
            // Never completed a delegated login, so nothing is published.
            return report(row, PlacementShadowResult.MAS_NONE, null, null, "no_mas_link", false);
        }
        if (homes.size() > 1) {
            return report(row, PlacementShadowResult.MAS_MULTIPLE, null, null, "multiple_links", false);
        }

        String masHome = homes.iterator().next();
        HomeserverConfig homeserver = byFederationId.get(masHome);
        MasLink link = links.get(0);

        if (homeserver == null) {
            throw new UnknownHomeserverException(masHome);
        }
        if (!row.userId().endsWith(":" + homeserver.getDomain())) {
            // The account's own id names one homeserver and its link lives on another.
            return report(row, PlacementShadowResult.MAS_MULTIPLE, masHome, null, "subject_home_mismatch",
                    false);
        }
        if (link.masUsername() != null && !link.masUsername().isBlank()
                && !composeUserId(homeserver, link.masUsername()).equals(row.userId())) {
            // Composed forward from the MAS username: localparts are derived in exactly one place and this is
            // not it.
            return report(row, PlacementShadowResult.MAS_USERNAME_MISMATCH, masHome, null, "username_merge",
                    false);
        }

        Optional<PlacementRecord> published = findRecord(row.accountId());
        String recordHome = published.map(PlacementRecord::homeserverId).orElse(null);
        if (recordHome != null && !recordHome.equals(masHome)) {
            return report(row, PlacementShadowResult.RECORD_DISAGREES, masHome, recordHome, "record_conflict",
                    false);
        }

        String directoryHome = directoryFederationId(row);
        boolean directoryAgrees = masHome.equals(directoryHome);
        PlacementShadowResult result;
        String reason;
        boolean known = false;
        if (!directoryAgrees) {
            known = masHome.equals(shadow.getKnownPlacements().get(row.userId()));
            result = PlacementShadowResult.DIRECTORY_STALE;
            reason = "local_choice=" + directoryHome;
        } else if (published.isEmpty()) {
            result = PlacementShadowResult.RECORD_MISSING;
            reason = "no_record";
        } else {
            result = PlacementShadowResult.AGREE;
            reason = null;
        }

        // Publishing is decided from the evidence, not from the classification.
        maybePublish(row, masHome, published, now);
        maybeHeal(row, masHome, homeserver, shadow, result, known);

        return report(row, result, masHome, recordHome, reason, known);
    }

    static final class UnknownHomeserverException extends RuntimeException {

        private final transient String homeserverId;

        UnknownHomeserverException(String homeserverId) {
            super("No configured homeserver has federation roster id " + homeserverId);
            this.homeserverId = homeserverId;
        }

        String homeserverId() {
            return homeserverId;
        }
    }

    private void maybePublish(PlacementAccountScanner.AccountRow row, String masHome,
            Optional<PlacementRecord> published, Instant now) {
        if (!properties.getPlacement().getPublish().isEnabled()) {
            return;
        }
        boolean due = published.isEmpty() || isDueForReissue(published.get(), now);
        if (!due) {
            return;
        }
        if (!signer.canSignFor(masHome)) {
            metrics.published("no_signing_key");
            return;
        }
        AccountId accountId;
        byte origin;
        try {
            accountId = AccountId.parse(row.accountId());
            origin = accountId.rootClass();
        } catch (InvalidGenesisException ex) {
            log.error("placement_publish_skipped accountId={} reason=unreadable_account_id", row.accountId());
            metrics.published("bad_account_id");
            return;
        }
        if (!originMatches(row.origin(), accountId)) {
            log.error("placement_publish_skipped accountId={} reason=origin_class_mismatch storedOrigin={}",
                    row.accountId(), row.origin());
            metrics.published("origin_mismatch");
            return;
        }

        ResolverPlacementClient.PublishOutcome outcome =
                resolver.publish(signer.sign(accountId, origin, masHome, now));
        metrics.published(outcome.name().toLowerCase(java.util.Locale.ROOT));
        if (outcome == ResolverPlacementClient.PublishOutcome.CONFLICT) {
            log.error("placement_conflict accountId={} userId={} masHomeserver={}", row.accountId(),
                    row.userId(), masHome);
        }
    }

    private void maybeHeal(PlacementAccountScanner.AccountRow row, String masHome,
            HomeserverConfig homeserver, ShadowProperties shadow, PlacementShadowResult result,
            boolean known) {
        if (!shadow.isHealDirectory() || result != PlacementShadowResult.DIRECTORY_STALE || known) {
            return;
        }
        // The value comes from the MAS link. Routing state must never be derived from a published record.
        int updated = scanner.healDirectoryHomeserver(row.userId(), homeserver.getId());
        log.info("placement_directory_healed userId={} homeserver={} masHomeserver={} rows={}",
                row.userId(), homeserver.getId(), masHome, updated);
    }

    private PlacementShadowResult report(PlacementAccountScanner.AccountRow row, PlacementShadowResult result,
            String masHome, String recordHome, String reason, boolean known) {
        if (result == PlacementShadowResult.AGREE) {
            return result;
        }
        String message = "placement_shadow result={} accountId={} userId={} origin={} directoryHomeserver={} "
                + "masHomeserver={} recordHomeserver={} reason={} known={}";
        Object[] fields = { result.tag(), row.accountId(), row.userId(), row.origin(),
                row.directoryHomeserverId(), masHome, recordHome, reason, known };
        if (result.isCorrectnessEvent()) {
            log.error(message, fields);
        } else if (known) {
            log.info(message, fields);
        } else {
            log.warn(message, fields);
        }
        return result;
    }

    private boolean isDueForReissue(PlacementRecord record, Instant now) {
        return record.issuedAt().plus(properties.getPlacement().getReissueAfter()).isBefore(now);
    }

    private Optional<PlacementRecord> findRecord(String accountId) {
        return resolver.findRecord(accountId);
    }

    private static String composeUserId(HomeserverConfig homeserver, String localpart) {
        return "@" + localpart + ":" + homeserver.getDomain();
    }

    private boolean originMatches(String storedOrigin, AccountId accountId) {
        if ("GENESIS".equals(storedOrigin)) {
            return accountId.isGenesisRooted();
        }
        if ("BOOTSTRAP".equals(storedOrigin)) {
            return !accountId.isGenesisRooted();
        }
        return false;
    }

    /** A null or legacy local value means the legacy homeserver. */
    private String directoryFederationId(PlacementAccountScanner.AccountRow row) {
        String registryId = row.directoryHomeserverId();
        if (registryId == null || registryId.isBlank()) {
            registryId = HomeserverRegistry.LEGACY_ID;
        }
        return signer.federationIdForRegistryId(registryId);
    }

    private Map<String, HomeserverConfig> indexByFederationId() {
        Map<String, HomeserverConfig> index = new LinkedHashMap<>();
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            index.put(signer.federationIdOf(homeserver), homeserver);
        }
        return index;
    }

    /** Null when the deployment has granted neither read path. */
    private MasLinkReader configuredReader() {
        for (MasLinkReader reader : readers) {
            if (reader.isConfigured()) {
                return reader;
            }
        }
        return null;
    }
}
