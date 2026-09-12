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

/**
 * Compares, for every account, where this service thinks it lives against where it actually lives, and
 * publishes a generation-1 placement record for the accounts whose evidence is unambiguous (ADM-008
 * decision 9, Phase 4).
 *
 * <p>This runs here because identity-service is the only component holding both halves of the join: the
 * phone digest to Matrix user id to accountId mapping, and its own homeserver choice. Neither the
 * resolver nor any MAS can make this comparison alone.
 *
 * <h2>What is compared</h2>
 * <ul>
 *   <li><b>D</b>, this service's local routing choice, from the account's most recent directory row. A
 *       null or {@code default} value means the legacy homeserver, and the alias map says which roster
 *       id that is.</li>
 *   <li><b>M</b>, the homeservers whose MAS holds a link for this account. Links with no MAS user are
 *       unfinished logins and are dropped. This is the only committed evidence of placement.</li>
 *   <li><b>U</b>, the MAS username behind that link, checked by composing the Matrix user id it implies
 *       and comparing, which also cross-checks the server name the account's own id carries.</li>
 *   <li><b>R</b>, the published record, read back and decoded.</li>
 * </ul>
 *
 * <h2>Two things this must never do</h2>
 * <p>It never logs a phone number. The scan selects no phone column, nothing downstream carries one, and
 * the structured line below names an accountId, a Matrix user id and homeserver ids only. It also never
 * reads the MAS column that holds a phone in the deployed configuration; see {@link MasSqlLinkReader}.
 *
 * <p>Nothing here feeds the resolution path. A published record is read for comparison and for the
 * re-issue decision, and for nothing else; the directory heal, when it is switched on, takes its value
 * from the MAS link and never from a record, so no routing decision can be traced back to placement
 * state. That is the explicit non-goal of this phase, and the guard test holds it.
 */
@Component
public class PlacementShadowReconciler {

    private static final Logger log = LoggerFactory.getLogger(PlacementShadowReconciler.class);

    /**
     * What an operator has to do to make this job runnable. Printed in full rather than as a code,
     * because the job cannot run at all until one of the two paths is granted.
     */
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

    /**
     * Daily, and only when the scheduler is on at all: {@code PlacementSchedulingConfig} gates
     * {@code @EnableScheduling} on the same flag, so with the feature off this method is never invoked.
     */
    @Scheduled(cron = "${identity.placement.shadow.cron:0 20 3 * * *}")
    public void reconcileOnSchedule() {
        reconcile();
    }

    /**
     * Runs one comparison to completion.
     *
     * @return the count per classification, empty when the job refused to run
     */
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
        String cursor = "";

        while (true) {
            List<PlacementAccountScanner.AccountRow> batch = scanner.nextBatch(cursor, shadow.getBatchSize());
            if (batch.isEmpty()) {
                break;
            }
            for (PlacementAccountScanner.AccountRow row : batch) {
                scanned++;
                PlacementShadowResult result = examine(row, reader, byFederationId, shadow, now);
                counts.merge(result, 1, Integer::sum);
                metrics.classified(result);
            }
            cursor = batch.get(batch.size() - 1).userId();
        }

        metrics.localpartOnConflict(reader.localpartOnConflictByHomeserver());
        metrics.runCompleted(scanned, now.getEpochSecond());
        log.info("Placement shadow comparison complete: scanned={} results={} readPath={}", scanned, counts,
                reader.describe());
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
            // Never completed a delegated login. Publishing nothing is deliberate: the MAS link is the
            // only committed evidence, and the Matrix user id is a name rather than a proof.
            return report(row, PlacementShadowResult.MAS_NONE, null, null, "no_mas_link", false);
        }
        if (homes.size() > 1) {
            return report(row, PlacementShadowResult.MAS_MULTIPLE, null, null, "multiple_links", false);
        }

        String masHome = homes.iterator().next();
        HomeserverConfig homeserver = byFederationId.get(masHome);
        MasLink link = links.get(0);

        if (homeserver != null && !row.userId().endsWith(":" + homeserver.getDomain())) {
            // The account's own id names one homeserver and its link lives on another: the same "one
            // subject, two homeservers" finding, and equally not something to publish a record for.
            return report(row, PlacementShadowResult.MAS_MULTIPLE, masHome, null, "subject_home_mismatch",
                    false);
        }
        if (homeserver != null && link.masUsername() != null && !link.masUsername().isBlank()
                && !composeUserId(homeserver, link.masUsername()).equals(row.userId())) {
            // Composed forward, from the MAS username to the Matrix user id it implies, rather than by
            // taking a localpart out of the id: this service derives localparts in exactly one place and
            // a comparison job is not it.
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

        // Publishing is decided from the evidence, not from the classification, so a stale local routing
        // row does not stop a record being written for an account whose evidence is otherwise clean.
        maybePublish(row, masHome, published, now);
        maybeHeal(row, masHome, byFederationId, shadow, result, known);

        return report(row, result, masHome, recordHome, reason, known);
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
            // This deployment does not hold that homeserver's membership key, so it is not the party
            // entitled to assert where the account lives.
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
            // The stored audit marker and the class byte inside the id must agree, or a bootstrap
            // account could be published as a rooted one.
            log.error("placement_publish_skipped accountId={} reason=origin_class_mismatch storedOrigin={}",
                    row.accountId(), row.origin());
            metrics.published("origin_mismatch");
            return;
        }

        ResolverPlacementClient.PublishOutcome outcome =
                resolver.publish(signer.sign(accountId, origin, masHome, now));
        metrics.published(outcome.name().toLowerCase(java.util.Locale.ROOT));
        if (outcome == ResolverPlacementClient.PublishOutcome.CONFLICT) {
            // One accountId has one home. A conflict is never retried and never forced; it is a person's
            // problem to explain, and moving an account between homeservers is refused outright.
            log.error("placement_conflict accountId={} userId={} masHomeserver={}", row.accountId(),
                    row.userId(), masHome);
        }
    }

    private void maybeHeal(PlacementAccountScanner.AccountRow row, String masHome,
            Map<String, HomeserverConfig> byFederationId, ShadowProperties shadow,
            PlacementShadowResult result, boolean known) {
        if (!shadow.isHealDirectory() || result != PlacementShadowResult.DIRECTORY_STALE || known) {
            return;
        }
        HomeserverConfig homeserver = byFederationId.get(masHome);
        if (homeserver == null) {
            return;
        }
        // The value written is this deployment's own registry id, taken from the MAS link. No published
        // record is consulted: routing state must never be derived from placement records in this phase.
        int updated = scanner.healDirectoryHomeserver(row.userId(), homeserver.getId());
        log.info("placement_directory_healed userId={} homeserver={} rows={}", row.userId(),
                homeserver.getId(), updated);
    }

    private PlacementShadowResult report(PlacementAccountScanner.AccountRow row, PlacementShadowResult result,
            String masHome, String recordHome, String reason, boolean known) {
        if (result == PlacementShadowResult.AGREE) {
            return result;
        }
        // One structured line per account that does not agree. No phone number, masked or otherwise,
        // reaches this line: the scan never selected one.
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

    /** The record is re-issued well before it expires, so a lapse needs a long outage rather than a day. */
    private boolean isDueForReissue(PlacementRecord record, Instant now) {
        return record.issuedAt().plus(properties.getPlacement().getReissueAfter()).isBefore(now);
    }

    private Optional<PlacementRecord> findRecord(String accountId) {
        return resolver.findRecord(accountId);
    }

    /** Composition, from a localpart to the Matrix user id it implies. */
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

    /** A null or legacy local value means the legacy homeserver; the alias map says which roster id that is. */
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

    /** The single configured read path, or null when the deployment has granted neither. */
    private MasLinkReader configuredReader() {
        for (MasLinkReader reader : readers) {
            if (reader.isConfigured()) {
                return reader;
            }
        }
        return null;
    }
}
