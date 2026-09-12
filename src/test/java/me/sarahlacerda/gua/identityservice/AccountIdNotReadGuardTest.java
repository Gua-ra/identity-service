package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase 3 derives, stores and audits an accountId and reads it for nothing else (ADM-008 decisions 9
 * and 10, migration plan Phase 3).
 *
 * <p>The hazard is specific. MAS derives the Matrix localpart from an arbitrary Jinja template over the
 * imported claims, so any new claim is one config line away from becoming the localpart; and an
 * accountId is lowercase letters and digits, so it would pass MAS's localpart rules. A claim, a
 * userinfo field or a directory column carrying an accountId would therefore be one deploy away from
 * re-keying accounts. This guard fails if the accountId reaches any file on the routing, login or claim
 * path.
 */
class AccountIdNotReadGuardTest {

    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");

    /** The only files allowed to name the type or the field at all. */
    private static final Set<String> ALLOWED = Set.of(
            // the codec itself
            "AccountId.java", "AccountGenesis.java", "AccountGenesisCodec.java", "BootstrapGenesis.java",
            "BootstrapGenesisCodec.java", "GenesisProofs.java", "Base32.java", "Ed25519Keys.java",
            "InvalidGenesisException.java",
            // storage and the registration endpoint
            "AccountGenesisRecord.java", "AccountGenesisRepository.java", "AccountGenesisService.java",
            "AccountCreationService.java", "AccountGenesisController.java", "AccountGenesisMetrics.java",
            "AccountGenesisRegisterRequest.java", "AccountGenesisRegisterResponse.java",
            "BootstrapAccountIdBackfill.java", "AccountScanner.java",
            // properties and error mapping carry the names in configuration and codes only
            "IdentityServiceProperties.java", "GenesisRegistrationException.java", "RestExceptionHandler.java");

    /**
     * Files on the paths that must never learn an accountId: everything that decides where an account
     * lives, who it is, or what MAS is told about it.
     */
    private static final Set<String> ROUTING_AND_LOGIN_PATH = Set.of(
            "OidcTokenService.java", "OidcAuthorization.java", "OidcAuthorizationService.java",
            "OidcUserInfoController.java", "OidcAuthorizationController.java", "LoginFlowController.java",
            "LoginSession.java", "AccountLocalpartResolver.java", "MatrixIds.java", "DirectoryService.java",
            "DirectoryEntry.java", "DirectoryController.java", "MatrixProvisioningService.java",
            "DefaultHomeserverRouter.java", "HomeserverRouter.java", "HomeserverRegistry.java",
            "AccountPlacementContext.java", "SecurityController.java", "UserSecurityService.java");

    private static final Pattern ACCOUNT_ID = Pattern.compile("\\b[Aa]ccountId\\b");

    @Test
    void noRoutingOrLoginPathFileNamesAnAccountId() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            if (!ROUTING_AND_LOGIN_PATH.contains(name)) {
                continue;
            }
            for (String line : codeLines(file)) {
                if (ACCOUNT_ID.matcher(line).find()) {
                    offenders.add(name + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void onlyTheGenesisFilesNameAnAccountIdAtAll() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            if (ALLOWED.contains(name)) {
                continue;
            }
            for (String line : codeLines(file)) {
                if (ACCOUNT_ID.matcher(line).find()) {
                    offenders.add(name + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void noClaimOrUserinfoFieldCarriesAnAccountId() throws IOException {
        // Belt and braces over the file-name list: whatever the claim builders are called, none of them
        // may mention a genesis or an accountId.
        for (String name : Set.of("OidcTokenService.java", "OidcUserInfoController.java", "OidcAuthorization.java")) {
            Path file = mainSources().stream()
                    .filter(path -> path.getFileName().toString().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("expected to find " + name));
            String code = String.join("\n", codeLines(file)).toLowerCase(java.util.Locale.ROOT);

            assertThat(code).as(name).doesNotContain("accountid").doesNotContain("genesis");
        }
    }

    @Test
    void theDirectoryRowHasNoAccountIdColumn() throws IOException {
        Path entity = mainSources().stream()
                .filter(path -> path.getFileName().toString().equals("DirectoryEntry.java"))
                .findFirst()
                .orElseThrow();
        String code = String.join("\n", codeLines(entity)).toLowerCase(java.util.Locale.ROOT);

        assertThat(code).doesNotContain("account_id").doesNotContain("accountid");
    }

    /** The account-creation path must reach the accountId only through the genesis service. */
    @Test
    void theLoginFlowTouchesGenesisOnlyThroughTheGenesisServices() throws IOException {
        Path controller = mainSources().stream()
                .filter(path -> path.getFileName().toString().equals("LoginFlowController.java"))
                .findFirst()
                .orElseThrow();
        String code = String.join("\n", codeLines(controller));

        assertThat(code).contains("accountCreationService.createAccount(");
        assertThat(code).doesNotContain("AccountGenesisRepository");
        assertThat(code).doesNotContain("AccountGenesisCodec");
    }

    private static List<Path> mainSources() throws IOException {
        assertThat(MAIN_SOURCES).as("run from the identity-service project directory").isDirectory();
        try (Stream<Path> paths = Files.walk(MAIN_SOURCES)) {
            List<Path> files = paths.filter(path -> path.toString().endsWith(".java")).toList();
            assertThat(files).isNotEmpty();
            return files;
        }
    }

    /** Trimmed source lines with comment-only lines and trailing line comments removed. */
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
