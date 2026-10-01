// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import me.sarahlacerda.gua.identityservice.security.OidcAccessTokenAuthenticationFilter;
import me.sarahlacerda.gua.identityservice.security.OidcAccessTokenValidator;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Source-level guards: no authority path accepts phone possession, directly or through a factor that an account
 * recovery has just minted.
 */
class AccountAuthorityGuardTest {

    private static final Path MAIN = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice");

    private static final List<Path> AUTHORITY_SOURCES = List.of(
            MAIN.resolve("account/authority"),
            MAIN.resolve("service/authority"),
            MAIN.resolve("controller/AccountAuthorityController.java"),
            MAIN.resolve("controller/AccountAuthorityNotificationController.java"));

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
        assertThat(holds).isGreaterThan(accepted);
        assertThat(minted).isGreaterThan(holds);
    }

    @Test
    void submittingARecordWeighsBothHoldsAgain() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String body = methodBody(service, "private Submitted submit(");

        assertThat(body).contains("policy.enforceFreshFactorHold(spent.factorCreatedAt())");
        assertThat(body).contains("policy.enforceRecoveryOutsideHold(userId)");
    }

    @Test
    void theHoldNeverGatesAnOpposition() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        for (String method : new String[] { "public void oppose(", "public void opposeWithRecord(" }) {
            String body = methodBody(service, method);
            assertThat(body).as("in %s", method).doesNotContain("enforceFreshFactorHold");
            assertThat(body).as("in %s", method).doesNotContain("enforceRecoveryOutsideHold");
            assertThat(body).as("in %s", method).doesNotContain("enforceHolds");
        }

        String stepUps = read(MAIN.resolve("service/authority/AuthorityStepUpService.java"));
        assertThat(methodBody(stepUps, "public void enforceHolds(")).contains("Purpose.OPPOSE");
    }

    @Test
    void anOpposeIsNeverAppendedToTheChain() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));
        String policy = read(MAIN.resolve("service/authority/AuthorityPolicy.java"));

        String oppose = methodBody(service, "public void opposeWithRecord(");
        assertThat(oppose).doesNotContain("recordRepository.save(");
        assertThat(oppose).doesNotContain("head.place(");

        assertThat(methodBody(policy, "public void requirePermittedAt(")).contains("case OPPOSE -> false");
    }

    @Test
    void aGrantMayOnlyNameAKeyADeviceOfThisAccountOffered() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        String signer = methodBody(service, "private void requireSignerMayAct(");
        assertThat(signer).contains("policy.requireLiveCandidate(");
        assertThat(signer).contains("candidate.isLive(now)");
    }

    @Test
    void everyTransitionGoesThroughTheOneSubmissionPathRatherThanItsOwnBranches() throws IOException {
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

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
        assertThat(repository).doesNotContain("@Modifying");
    }

    @Test
    void everyAuthorityEndpointIsGatedOnTheFlag() throws IOException {
        String controller = read(MAIN.resolve("controller/AccountAuthorityController.java"));
        String service = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        long gatedInTheService = Stream.of("public AuthorityChallengeService.Minted challenge(",
                        "public Submitted adopt(", "public void oppose(", "public void opposeWithRecord(",
                        "public Submitted grantDevice(", "public Submitted revokeDevice(",
                        "public Submitted recoverAuthority(", "public AuthorityStateResponse state(",
                        "public Candidate registerCandidate(", "public List<Candidate> candidates(")
                .filter(method -> methodBody(service, method).contains("policy.requireEnabled()"))
                .count();
        assertThat(gatedInTheService).isEqualTo(10);

        String registry = read(MAIN.resolve("service/authority/AuthorityNotificationRegistry.java"));
        for (String method : new String[] { "public Registered register(", "public String remove(",
                "public List<AuthorityNotificationRegistration> listForHolder(" }) {
            assertThat(methodBody(registry, method)).as("flag gates in %s", method)
                    .contains("policy.requireEnabled()")
                    .contains("policy.requireNotificationsEnabled()");
        }

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

        assertThat(offenders).isEmpty();
    }

    @Test
    void theRecoveryStampIsWrittenWhereARecoveryCompletesAndReadOnlyByTheChain() throws IOException {
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String policy = read(MAIN.resolve("service/authority/AuthorityPolicy.java"));

        String complete = methodBody(recovery, "public int complete(");
        assertThat(complete).contains("lockUser(userId)");
        assertThat(complete).contains("recordRecoveryCompleted(user, now)");
        assertThat(userSecurity).contains("recoveryCompletionHoldRemaining");
        assertThat(policy).contains("userSecurityService.recoveryCompletionHoldRemaining(userId)");
    }

    @Test
    void theAuthorityStepUpPageHasTwoArmsAndNeitherIsAPhoneCode() throws IOException {
        String controller = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        assertThat(controller.split("@PostMapping\\(\"/authority/stepup", -1)).hasSize(4);
        assertThat(controller).contains("@PostMapping(\"/authority/stepup/passkey/options\")");
        assertThat(controller).contains("@PostMapping(\"/authority/stepup/passkey/verify\")");
        assertThat(controller).contains("@PostMapping(\"/authority/stepup/pin\")");
        assertThat(controller).doesNotContain("/authority/stepup/otp");

        for (String method : new String[] {
                "public ResponseEntity<PasskeyOptionsResponse> startAuthorityStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> finishAuthorityStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> submitAuthorityStepUpPin(",
                "private void requireAuthorityStepUp(",
                "private ResponseEntity<LoginStateResponse> acceptAuthorityStepUp(",
                "private ResponseEntity<LoginStateResponse> completeAuthorityStepUp(" }) {
            String body = methodBody(controller, method);
            assertThat(body).as("in %s", method)
                    .doesNotContain("otpService")
                    .doesNotContain("accountReauthService")
                    .doesNotContain("PHONE_OTP")
                    .doesNotContain("recoveryAvailable");
        }

        assertThat(methodBody(controller, "public ResponseEntity<LoginStateResponse> finishAuthorityStepUpPasskey("))
                .contains("AuthFactor.PASSKEY");
        assertThat(methodBody(controller, "public ResponseEntity<LoginStateResponse> submitAuthorityStepUpPin("))
                .contains("AuthFactor.PIN");
        assertThat(methodBody(read(MAIN.resolve("service/authority/AuthorityWebStepUpService.java")),
                "public Instant proved(String userId, String sessionHash, Purpose purpose"))
                .contains("factor != AuthFactor.PASSKEY && factor != AuthFactor.PIN");
    }

    @Test
    void aWebStepUpIsBoundToTheAccountTheSessionAndThePurposeAndSpentOnce() throws IOException {
        String service = read(MAIN.resolve("service/authority/AuthorityWebStepUpService.java"));
        String repository = read(Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice",
                "repository", "AuthorityWebStepUpRepository.java"));

        assertThat(repository).contains("findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull");
        assertThat(repository).doesNotContain("findByUserId(");
        assertThat(repository).doesNotContain("findByPurpose");

        String consume = methodBody(service, "public Optional<Proved> consume(");
        assertThat(consume).contains("setConsumedAt(now)");
        assertThat(consume).contains("repository.save(stepUp)");
        assertThat(consume.indexOf("setConsumedAt(now)")).isLessThan(consume.indexOf("return Optional.of("));
        assertThat(service).contains("@Transactional(propagation = Propagation.REQUIRES_NEW)");

        String burn = read(MAIN.resolve("service/authority/AuthorityChallengeBurn.java"));
        assertThat(burn).contains("@Transactional(propagation = Propagation.REQUIRES_NEW)");
        assertThat(methodBody(read(MAIN.resolve("service/authority/AuthorityChallengeService.java")),
                "public Spent spend(")).contains("burn.burn(");

        assertThat(methodBody(service, "public Instant proved(String userId, String sessionHash, Purpose purpose"))
                .contains("policy.challengeTtl()");
    }

    @Test
    void theSheetIsConsultedOnlyForARequestThatProvedNothingAndOnlyForATransition() throws IOException {
        String stepUps = read(MAIN.resolve("service/authority/AuthorityStepUpService.java"));
        String webStepUps = read(MAIN.resolve("service/authority/AuthorityWebStepUpService.java"));
        String policy = read(MAIN.resolve("service/authority/AuthorityPolicy.java"));
        String authority = read(MAIN.resolve("service/authority/AccountAuthorityService.java"));

        String scoped = methodBody(stepUps, "public Accepted accept(String userId, Purpose purpose");
        int gate = scoped.indexOf("!presentedSomething(passkeyStepUpId, passkeyCredential, pin)");
        assertThat(gate).isPositive();
        assertThat(scoped.indexOf("webStepUps.consume(")).isGreaterThan(gate);
        assertThat(scoped).contains("stepUp.accepts(proved.factor())");

        assertThat(methodBody(policy, "public boolean canOpenStepUpSheet("))
                .contains("stepUpFor(purpose).required()");
        assertThat(methodBody(webStepUps, "public void requireMayOpen("))
                .contains("policy.requireEnabled()")
                .contains("policy.requireNativeSession(clientId)")
                .contains("policy.requireStepUpSheetPurpose(purpose)");
        assertThat(methodBody(webStepUps, "public void requireOpen(")).contains("policy.requireEnabled()");

        assertThat(methodBody(authority, "public AuthorityChallengeService.Minted challenge("))
                .contains("stepUps.accept(userId, purpose, sessionHash,");
    }

    @Test
    void aCookieAuthenticatedCallerCannotReachAnAuthorityEndpoint() throws Exception {
        OidcAccessTokenValidator validator = org.mockito.Mockito.mock(OidcAccessTokenValidator.class);
        OidcAccessTokenAuthenticationFilter filter =
                new OidcAccessTokenAuthenticationFilter(validator, List.of());

        for (String path : new String[] { "/account/authority/adopt", "/account/authority/oppose",
                "/account/authority/oppose/record", "/account/authority/device/grant",
                "/account/authority/device/revoke", "/account/authority/recover",
                "/account/authority/challenge", "/account/security-notifications",
                "/account/security-notifications/remove" }) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
            request.setCookies(new jakarta.servlet.http.Cookie("gua_login_session", "a-live-login-session"));
            request.addHeader("X-CSRF-Token", "a-live-csrf-token");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(response.getStatus()).as("%s", path).isEqualTo(401);
            assertThat(chain.getRequest()).as("%s reached the handler", path).isNull();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).as("%s", path).isNull();
            org.mockito.Mockito.verifyNoInteractions(validator);
        }
        SecurityContextHolder.clearContext();

        String security = read(Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice",
                "config", "SecurityConfig.java"));
        for (String list : new String[] { "OPEN_POST_ENDPOINTS", "RETIRED_POST_ENDPOINTS", "OPEN_GET_ENDPOINTS" }) {
            String body = security.substring(security.indexOf(list), security.indexOf(";", security.indexOf(list)));
            assertThat(body).as("%s", list).doesNotContain("/account/authority")
                    .doesNotContain("/account/security-notifications");
        }
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

    /** Brace-counted with string literals skipped, so an inner block or a brace in a message cannot truncate it. */
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
