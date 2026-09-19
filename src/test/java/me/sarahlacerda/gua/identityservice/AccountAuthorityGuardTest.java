// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Freezes the three source rules ADM-009 decision 9 names, because the laundering path they close never presents
 * an OTP to an authority endpoint at all.
 *
 * <p>The guard has to be wider than the adoption endpoint. The attack is: a SIM swap completes an account
 * recovery, which deletes every passkey, sets a caller-chosen PIN and revokes the account's sessions in one
 * transaction; the attacker then signs in normally and presents that PIN as the possession proof for rooting or
 * moving the account. Nothing in that sequence puts a phone code in an authority request, so a rule written
 * about the request body would not fire. The three rules are therefore:
 *
 * <ol>
 * <li>no authority endpoint may reference the OTP services;</li>
 * <li>{@code AuthFactor.PHONE_OTP} may not appear in any accepted set for an authority operation;</li>
 * <li>no authority-granting record is accepted on a factor inside the fresh-factor hold, or while the account's
 * last completed account recovery is inside it.</li>
 * </ol>
 *
 * <p>Written in the shape of {@code AuthFactorPolicyGuardTest}, including its brace-counting
 * {@code methodBody} helper, because the hazard is the same: these are decisions not visible in the behaviour
 * of a single method, and a match anywhere in a file is not a guard.
 */
class AccountAuthorityGuardTest {

    private static final Path MAIN = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice");

    /** Every file of the feature: the codec package, the service package, and the controller. */
    private static final List<Path> AUTHORITY_SOURCES = List.of(
            MAIN.resolve("account/authority"),
            MAIN.resolve("service/authority"),
            MAIN.resolve("controller/AccountAuthorityController.java"));

    /**
     * The OTP surface, by the names an authority file would have to write to reach it. {@code OtpScope} and
     * {@code OtpCodes} are included because they are how a caller would namespace a code rather than send one,
     * and {@code AccountReauthService} and {@code ReauthTokenService} because both are minted by an SMS code:
     * reusing either would put phone possession at the root of an authority transition, which is the whole
     * lesson of the design ADM-008 rejected.
     */
    private static final List<String> OTP_SURFACE = List.of(
            "OtpService", "OtpCodes", "OtpScope", "OtpController", "SmsSender", "AccountReauthService",
            "ReauthTokenService", "ReauthOperation", "PhoneNumberNormalizer", "PhoneNumberHasher");

    @Test
    void noAuthorityFileReferencesTheOtpServices() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : authorityFiles()) {
            String code = String.join("\n", codeLines(file));
            for (String name : OTP_SURFACE) {
                if (code.contains(name)) {
                    offenders.add(file.getFileName() + ": " + name);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void noAuthorityFileEvenNamesThePhoneCode() throws IOException {
        // Rule 2, stated at its widest. The value cannot appear in an accepted set if it appears nowhere, and
        // "nowhere" is a claim a reader can check in one line.
        List<String> offenders = new ArrayList<>();
        for (Path file : authorityFiles()) {
            for (String line : codeLines(file)) {
                if (line.contains("PHONE_OTP")) {
                    offenders.add(file.getFileName() + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void everyAcceptedSetForAnAuthorityOperationIsThePasskeyAndThePinAndNothingElse() throws IOException {
        String policy = read(MAIN.resolve("service/authority/AuthorityPolicy.java"));

        String stepUp = methodBody(policy, "public StepUpPolicy stepUpFor(");
        String opposition = methodBody(policy, "public StepUpPolicy oppositionStepUp(");

        for (String body : new String[] { stepUp, opposition }) {
            assertThat(body).doesNotContain("PHONE_OTP");
            assertThat(body).doesNotContain("AuthFactor.values()");
        }
        assertThat(stepUp).contains("AuthFactor.PASSKEY").contains("AuthFactor.PIN");
        assertThat(opposition).contains("AuthFactor.PASSKEY").contains("AuthFactor.PIN");
    }

    @Test
    void mintingAChallengeWeighsBothHoldsBeforeItReturnsOne() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String body = methodBody(service, "public AuthorityChallengeService.Minted challenge(");

        int accepted = body.indexOf("stepUps.accept(");
        int holds = body.indexOf("stepUps.enforceHolds(");
        int minted = body.indexOf("challenges.mint(");

        assertThat(accepted).isPositive();
        // After the factor is known to be the caller's own, and before anything signable is handed out.
        assertThat(holds).isGreaterThan(accepted);
        assertThat(minted).isGreaterThan(holds);
    }

    @Test
    void submittingARecordWeighsBothHoldsAgain() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String body = methodBody(service, "private Submitted submit(");

        // Rule 3. Re-weighed at submission and not only at minting, because a recovery can complete in
        // between and the point of the rule is that the two clocks compose.
        assertThat(body).contains("policy.enforceFreshFactorHold(spent.factorCreatedAt())");
        assertThat(body).contains("policy.enforceRecoveryOutsideHold(userId)");
    }

    @Test
    void theHoldNeverGatesAnOpposition() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String body = methodBody(service, "public void oppose(");

        // An owner who has just changed their PIN to lock a thief out must not be the one disarmed by it.
        assertThat(body).doesNotContain("enforceFreshFactorHold");
        assertThat(body).doesNotContain("enforceRecoveryOutsideHold");
        assertThat(body).doesNotContain("enforceHolds");
    }

    @Test
    void everyTransitionGoesThroughTheOneSubmissionPathRatherThanItsOwnBranches() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        // Revision 2's holes were all of the same shape: a control written for one record type and missing
        // from another. One path is what makes "every record signs a challenge" checkable.
        for (String method : new String[] { "public Submitted adopt(", "public Submitted grantDevice(",
                "public Submitted revokeDevice(", "public Submitted recoverAuthority(" }) {
            String body = methodBody(service, method);
            assertThat(body).as("in %s", method).contains("submit(userId, sessionHash, Purpose.");
            assertThat(body).as("in %s", method).contains("policy.requireEnabled()");
        }
        String submit = methodBody(service, "private Submitted submit(");
        assertThat(submit).contains("accounts.requireMatches(account, record.accountReference())");
        assertThat(submit).contains("challenges.spend(");
        assertThat(submit).contains("AuthorityProofs.verifyRecord(record, spent.challenge(), signature)");
    }

    @Test
    void theChallengeIsBurnedBeforeTheSignatureIsWeighed() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String body = methodBody(service, "private Submitted submit(");

        // Burned on acceptance and on refusal is one code path, not two: no arrangement of later failures can
        // leave a challenge spendable.
        assertThat(body.indexOf("challenges.spend(")).isLessThan(body.indexOf("AuthorityProofs.verifyRecord("));
    }

    @Test
    void everyWriteTakesTheHeadLockAndComparesAndSets() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        for (String method : new String[] { "private Submitted submit(", "public void oppose(",
                "public AuthorityStateResponse state(" }) {
            assertThat(methodBody(service, method)).as("head lock in %s", method).contains("lockHead(account,");
        }
        String submit = methodBody(service, "private Submitted submit(");
        assertThat(submit).contains("record.seq() != head.nextSeq()");
        assertThat(submit).contains("record.prevHashHex()");
        assertThat(submit).contains("authority_head_conflict");

        String lock = methodBody(service, "private AuthorityChainHead lockHead(");
        assertThat(lock).contains("findByAccountForUpdate");
    }

    @Test
    void theHeadIsOnlyEverReadForUpdateByAWriter() throws IOException {
        String repository = read(Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice",
                "repository", "AuthorityChainHeadRepository.java"));

        assertThat(repository).contains("PESSIMISTIC_WRITE");
        // Deliberately no @Modifying query: the compare-and-set is only a compare-and-set because the row was
        // read FOR UPDATE first.
        assertThat(repository).doesNotContain("@Modifying");
    }

    @Test
    void everyAuthorityEndpointIsGatedOnTheFlag() throws IOException {
        String controller = read(MAIN.resolve("controller/AccountAuthorityController.java"));
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        // Either the handler asks, or the service method it calls does. Checked as a set, because a handler
        // that delegates immediately has nothing else to check.
        long gatedInTheService = Stream.of("public AuthorityChallengeService.Minted challenge(",
                        "public Submitted adopt(", "public void oppose(", "public Submitted grantDevice(",
                        "public Submitted revokeDevice(", "public Submitted recoverAuthority(",
                        "public AuthorityStateResponse state(")
                .filter(method -> methodBody(service, method).contains("policy.requireEnabled()"))
                .count();
        assertThat(gatedInTheService).isEqualTo(7);

        for (String method : new String[] { "public ResponseEntity<AuthorityApprovalResponse> startApproval(",
                "public ResponseEntity<List<AuthorityApprovalView>> liveApprovals(",
                "public ResponseEntity<Void> signApproval(" }) {
            assertThat(methodBody(controller, method)).as("flag gate in %s", method)
                    .contains("policy.requireEnabled()");
        }
    }

    @Test
    void theBrowserSideOfTheFeatureSignsNothing() throws IOException {
        String approvals = read(MAIN.resolve("service/authority/AuthorityApprovalService.java"));

        // Decision 6 is a rule, not a default: there is no flag that lets a web session sign an authority
        // record, and this service only ever verifies a device's signature.
        assertThat(approvals).doesNotContain("initSign");
        assertThat(approvals).doesNotContain("PrivateKey");
        assertThat(approvals).contains("verifyApproval");
    }

    @Test
    void noFileOutsideTheFeatureReachesIntoTheChain() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            if (name.startsWith("Authority") || name.startsWith("AccountAuthority")
                    || name.equals("IdentityServiceProperties.java") || name.equals("RestExceptionHandler.java")) {
                continue;
            }
            for (String line : codeLines(file)) {
                if (line.contains("AuthorityChainHeadRepository") || line.contains("AuthorityChainRecordRepository")
                        || line.contains("AuthorityDeviceRepository") || line.contains("AccountAuthorityService")) {
                    offenders.add(name + ": " + line);
                }
            }
        }

        // The feature is additive. Nothing that existed before it reads its tables, so with the flag off there
        // is no path into them at all.
        assertThat(offenders).isEmpty();
    }

    @Test
    void theRecoveryStampIsWrittenWhereARecoveryCompletesAndReadOnlyByTheChain() throws IOException {
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String policy = read(MAIN.resolve("service/authority/AuthorityPolicy.java"));

        // Inside the completing transaction and under the same lock, so it cannot be left behind by a
        // rollback.
        String complete = methodBody(recovery, "public int complete(");
        assertThat(complete).contains("lockUser(userId)");
        assertThat(complete).contains("recordRecoveryCompleted(user, now)");
        assertThat(userSecurity).contains("recoveryCompletionHoldRemaining");
        assertThat(policy).contains("userSecurityService.recoveryCompletionHoldRemaining(userId)");
    }

    private static List<Path> authorityFiles() throws IOException {
        List<Path> files = new ArrayList<>();
        for (Path source : AUTHORITY_SOURCES) {
            if (Files.isDirectory(source)) {
                try (Stream<Path> paths = Files.walk(source)) {
                    files.addAll(paths.filter(path -> path.toString().endsWith(".java")).toList());
                }
            } else {
                assertThat(source).isRegularFile();
                files.add(source);
            }
        }
        assertThat(files).as("run from the identity-service project directory").isNotEmpty();
        return files;
    }

    private static List<Path> mainSources() throws IOException {
        try (Stream<Path> paths = Files.walk(MAIN)) {
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

    /**
     * The body of a named method, from its signature to its matching closing brace.
     *
     * <p>Brace-counted rather than cut at the first line closing at four spaces, and double-quoted strings are
     * skipped so a brace inside a message cannot unbalance the count. The cheap version returns a fragment the
     * moment a method grows an inner block, and every {@code doesNotContain} over a fragment passes for the
     * wrong reason. Copied from {@code AuthFactorPolicyGuardTest}, which is the house pattern for this.
     */
    private static String methodBody(String source, String signature) {
        int start = source.indexOf(signature);
        assertThat(start).as("method %s", signature).isPositive();
        int open = source.indexOf('{', start);
        assertThat(open).as("body of method %s", signature).isGreaterThan(start);
        int depth = 0;
        boolean inString = false;
        for (int i = open; i < source.length(); i++) {
            char current = source.charAt(i);
            if (inString) {
                if (current == '\\') {
                    i++;
                } else if (current == '"') {
                    inString = false;
                }
                continue;
            }
            if (current == '"') {
                inString = true;
            } else if (current == '{') {
                depth++;
            } else if (current == '}' && --depth == 0) {
                return source.substring(start, i + 1);
            }
        }
        throw new AssertionError("Unterminated method body for " + signature);
    }

    private static String read(Path path) throws IOException {
        return Files.readString(path);
    }
}
