// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase 4 computes, publishes and compares placement records, and serves nothing from them. That is an
 * explicit non-goal of the phase rather than an oversight, and this is the test the brief asks for.
 *
 * <p>The hazard is the obvious next step. Once an accountId-to-homeserver mapping exists in federation
 * state, reading it to answer a routing question is a small, tempting change; and it is exactly the
 * change no later phase may make until every shadow-mode exit criterion holds, because a record that is
 * merely published has been checked by nobody. So the resolution and login paths must not learn that
 * placement records exist at all, and there is deliberately no flag that would turn serving on.
 *
 * <p>The resolver enforces its own half, that its resolution path never reads the placement table. This
 * is the identity-service half: nothing that decides where an account lives, who it is, or what MAS is
 * told about it may reach a placement record.
 */
class PlacementRecordsNotServedGuardTest {

    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");
    private static final Path MAIN_RESOURCES = Path.of("src", "main", "resources");

    /** Everything that decides where an account lives, who it is, or what MAS is told about it. */
    private static final Set<String> ROUTING_AND_LOGIN_PATH = Set.of(
            "OidcTokenService.java", "OidcAuthorization.java", "OidcAuthorizationService.java",
            "OidcUserInfoController.java", "OidcAuthorizationController.java", "LoginFlowController.java",
            "LoginSession.java", "AccountLocalpartResolver.java", "MatrixIds.java", "DirectoryService.java",
            "DirectoryEntry.java", "DirectoryController.java", "MatrixProvisioningService.java",
            "DefaultHomeserverRouter.java", "HomeserverRouter.java", "HomeserverRegistry.java",
            "AccountPlacementContext.java", "SecurityController.java", "UserSecurityService.java",
            "AccountCreationService.java", "IdentityOrchestrationService.java", "ContactDiscoveryService.java",
            "SignInController.java", "SignupController.java");

    /**
     * The placement types by name. Matching these rather than the word "placement" is deliberate: the
     * routing code has always had an {@code AccountPlacementContext}, which is the local choice of a
     * homeserver for a new account and has nothing to do with a signed record.
     */
    private static final List<String> PLACEMENT_RECORD_TYPES = List.of(
            "PlacementRecord", "PlacementRecordCodec", "PlacementRecordSigner", "ResolverPlacementClient",
            "PlacementShadowReconciler", "PlacementAccountScanner", "PlacementShadowResult",
            "service.placement");

    @Test
    void noRoutingOrLoginPathFileReachesAPlacementRecord() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            if (!ROUTING_AND_LOGIN_PATH.contains(name)) {
                continue;
            }
            for (String line : codeLines(file)) {
                for (String type : PLACEMENT_RECORD_TYPES) {
                    if (line.contains(type)) {
                        offenders.add(name + ": " + line);
                    }
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void theRoutingAndLoginFilesThisGuardsReallyExist() throws IOException {
        // A guard that silently matched nothing would pass forever after a rename.
        List<String> present = mainSources().stream()
                .map(path -> path.getFileName().toString())
                .filter(ROUTING_AND_LOGIN_PATH::contains)
                .toList();

        assertThat(present).hasSameSizeAs(ROUTING_AND_LOGIN_PATH);
    }

    @Test
    void thereIsNoServeFromRecordsFlagAnywhere() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : Stream.concat(mainSources().stream(), resources().stream()).toList()) {
            String content = Files.readString(file).toLowerCase(Locale.ROOT);
            for (String forbidden : List.of("serve-from-records", "serve_from_records", "servefromrecords",
                    "serve-from-placement", "servefromplacement")) {
                if (content.contains(forbidden)) {
                    offenders.add(file.getFileName() + " mentions " + forbidden);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void theResolverClientOffersOnlyTheThreeOperationsThisPhaseNeeds() {
        List<String> methods = Arrays.stream(ResolverPlacementClient.class.getDeclaredMethods())
                .map(java.lang.reflect.Method::getName)
                .filter(name -> !name.startsWith("lambda$") && !name.startsWith("$"))
                .distinct()
                .sorted()
                .toList();

        // Reading the roster, reading one record back to compare, and publishing one. In particular
        // there is no call that would append a transparency-log leaf per record: anchoring is the
        // resolver's periodic checkpoint, and one leaf per record would churn its fallback placement.
        assertThat(methods).containsExactlyInAnyOrder("fetchRoster", "findRecord", "publish", "isConfigured");
    }

    @Test
    void nothingInThePlacementPackageAppendsToTheTransparencyLog() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            if (!file.toString().contains("service" + java.io.File.separator + "placement")) {
                continue;
            }
            for (String line : codeLines(file)) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.contains("checkpoint") || lower.contains("merkle") || lower.contains("transparency")) {
                    offenders.add(file.getFileName() + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void theDirectoryHealTakesItsValueFromTheEvidenceAndNeverFromARecord() throws IOException {
        Path reconciler = mainSources().stream()
                .filter(path -> path.getFileName().toString().equals("PlacementShadowReconciler.java"))
                .findFirst()
                .orElseThrow();
        String body = methodBody(Files.readString(reconciler), "private void maybeHeal(");

        // Healing writes routing state. If it ever read a published record, a routing decision would be
        // derived from placement state, which is the whole thing this phase does not do.
        assertThat(body).isNotBlank();
        assertThat(body).doesNotContain("published");
        assertThat(body).doesNotContain("PlacementRecord");
        assertThat(body).doesNotContain("findRecord");
        assertThat(body).contains("masHome");
    }

    /**
     * Source of one method, from its signature to the line that closes it at method indentation, with
     * comment lines removed. The comments are stripped because they are where this rule gets explained:
     * a sentence saying "no published record is consulted" would otherwise trip the assertion that the
     * code consults no published record.
     */
    private static String methodBody(String code, String signature) {
        int start = code.indexOf(signature);
        if (start < 0) {
            return "";
        }
        int end = code.indexOf("\n    }", start);
        if (end < 0) {
            return "";
        }
        return code.substring(start, end).lines()
                .map(String::trim)
                .filter(line -> !line.startsWith("//") && !line.startsWith("*") && !line.startsWith("/*"))
                .reduce("", (a, b) -> a + "\n" + b);
    }

    private static List<Path> mainSources() throws IOException {
        assertThat(MAIN_SOURCES).as("run from the identity-service project directory").isDirectory();
        try (Stream<Path> paths = Files.walk(MAIN_SOURCES)) {
            List<Path> files = paths.filter(path -> path.toString().endsWith(".java")).toList();
            assertThat(files).isNotEmpty();
            return files;
        }
    }

    private static List<Path> resources() throws IOException {
        try (Stream<Path> paths = Files.walk(MAIN_RESOURCES)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".yml") || path.toString().endsWith(".sql"))
                    .toList();
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
