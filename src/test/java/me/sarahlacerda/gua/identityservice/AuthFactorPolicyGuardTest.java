package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/** Source-text guards for decisions that are one edit away from a bypass or a lockout. */
class AuthFactorPolicyGuardTest {

    private static final Path MAIN = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice");

    @Test
    void theStepUpPathChecksTheUserVerifiedFlagOnTheAssertionItself() throws IOException {
        String redeem = methodBody(read(MAIN.resolve("service/security/PasskeyService.java")),
                "private PasskeyAuthentication redeemAssertion(");

        assertThat(redeem).contains("requireUserVerification && !result.isUserVerified()");
        assertThat(redeem).doesNotContain("UserVerificationRequirement");
    }

    /** A synced passkey's counter may never move, so validating it would lock those accounts out. */
    @Test
    void signatureCounterValidationStaysOff() throws IOException {
        String source = read(MAIN.resolve("service/security/PasskeyService.java"));

        assertThat(source).contains("validateSignatureCounter(false)");
    }

    @Test
    void signInAssertionsAreNotRaisedToTheStepUpBar() throws IOException {
        String source = read(MAIN.resolve("service/security/PasskeyService.java"));

        int loginStart = source.indexOf("public JsonNode startAuthentication(");
        int loginStartEnd = source.indexOf("public JsonNode startRegistration(") > loginStart
                ? source.indexOf("public JsonNode startRegistration(")
                : source.length();
        assertThat(loginStart).isPositive();
        String loginCeremony = source.substring(loginStart, Math.min(loginStartEnd, source.length()));
        assertThat(loginCeremony).contains("UserVerificationRequirement.PREFERRED");
    }

    @Test
    void thePinFlowsDoNotVerifyAgainstThePerPhoneOtpKey() throws IOException {
        String source = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));

        assertThat(source).doesNotContain("otpService.sendOtp(");
        assertThat(source).doesNotContain("otpService.verifyOtp(");
        assertThat(source).contains("OtpScope.PIN_CHANGE");
        assertThat(recovery).doesNotContain("OtpService");
        assertThat(recovery).doesNotContain("otpService");
    }

    @Test
    void theScopedOtpPathSharesTheCappedVerify() throws IOException {
        String source = read(MAIN.resolve("service/OtpService.java"));

        assertThat(source).contains("verifyScopedOtp");
        assertThat(source)
                .containsOnlyOnce("private void verify(String codeKey, String attemptsKey, String code, OtpVerifyFlow flow)");
        assertThat(source).containsOnlyOnce("countGuess(codeKey, attemptsKey)");
    }

    @Test
    void thePhoneChangeStepUpKeepsItsHardBlockAndItsOwnershipCheck() throws IOException {
        String source = read(MAIN.resolve("service/security/PhoneChangeService.java"));

        assertThat(source).contains("throw new StepUpRequiredException(");
        assertThat(source).contains("Passkey does not belong to the calling account");
        assertThat(source).contains("if (hasPin) {");
    }

    @Test
    void theStepUpTriesThePasskeyFirstThenThePinThenRefuses() throws IOException {
        String stepUp = methodBody(read(MAIN.resolve("service/security/PhoneChangeService.java")),
                "private void enforceStepUp(");

        int passkeyBranch = stepUp.indexOf("if (passkeyAttempted) {");
        int ownership = stepUp.indexOf("Passkey does not belong to the calling account");
        int pinBranch = stepUp.indexOf("if (hasPin) {");
        int hardBlock = stepUp.indexOf("throw new StepUpRequiredException(");

        assertThat(passkeyBranch).isPositive();
        assertThat(ownership).isGreaterThan(passkeyBranch).isLessThan(pinBranch);
        assertThat(pinBranch).isGreaterThan(passkeyBranch);
        assertThat(hardBlock).isGreaterThan(pinBranch);
    }

    @Test
    void theStepUpNeverConsultsPasskeyRegistration() throws IOException {
        String source = read(MAIN.resolve("service/security/PhoneChangeService.java"));

        assertThat(source).doesNotContain("hasPasskey");
        assertThat(source).doesNotContain("passkeyRegistered");
    }

    @Test
    void theAssertionChallengeIsBurnedOnRefusalAsWellAsOnAcceptance() throws IOException {
        String redeem = methodBody(read(MAIN.resolve("service/security/PasskeyService.java")),
                "private PasskeyAuthentication redeemAssertion(");

        int finallyBlock = redeem.indexOf("} finally {");
        assertThat(finallyBlock).isPositive();
        // In the finally, so no branch added later can return or throw past it.
        assertThat(redeem.indexOf("redisTemplate.delete(challengeKey)")).isGreaterThan(finallyBlock);
    }

    @Test
    void theStepUpRequestCarriesNoWayToClaimAFactorIsUnavailable() throws IOException {
        String source = read(MAIN.resolve("controller/dto/PhoneChangeStartRequest.java"));

        assertThat(source).doesNotContain("boolean");
        assertThat(source).doesNotContain("Boolean");
    }

    @Test
    void theFactorQuestionsAreAnsweredInOnePlace() throws IOException {
        String login = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String orchestration = read(MAIN.resolve("service/IdentityOrchestrationService.java"));
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));
        String phoneChange = read(MAIN.resolve("service/security/PhoneChangeService.java"));

        assertThat(login).doesNotContain("userSecurityService.hasPin(");
        assertThat(login).doesNotContain("passkeyService.hasPasskey(");
        assertThat(orchestration).doesNotContain("userSecurityService.hasPin(");
        assertThat(phoneChange).doesNotContain("userSecurityService.hasPin(");
        assertThat(security).doesNotContain("userSecurityService.hasPin(");
        assertThat(security).doesNotContain("passkeyService.hasPasskey(");
    }

    @Test
    void recoveryIsNotGatedOnHoldingAPasskey() throws IOException {
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String policy = methodBody(read(MAIN.resolve("service/security/AuthFactorPolicy.java")),
                "public RecoveryPolicy recoveryFor(");
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));

        assertThat(userSecurity).doesNotContain("Passkey");
        assertThat(userSecurity).doesNotContain("passkey");
        assertThat(policy).doesNotContain("if (");
        assertThat(policy).doesNotContain("throw ");
        assertThat(recovery).doesNotContain("hasPasskey");
        assertThat(recovery).doesNotContain("passkeyHeld");
        assertThat(recovery).doesNotContain("passkeyRegistered");
        assertThat(recovery).doesNotContain("hasPin");
        assertThat(methodBody(recovery, "public int complete(")).contains("passkeyService.removeAllForUser(userId)");
    }

    @Test
    void theBearerFirstPinIsRetiredInFavourOfTheEnrollmentStepUp() throws IOException {
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));
        String setInitialPin = methodBody(security, "public ResponseEntity<Void> setInitialPin(");

        assertThat(setInitialPin).contains("throw new StepUpRequiredException(");
        assertThat(setInitialPin).contains("/security/pin/enroll/start");
        assertThat(setInitialPin).doesNotContain("userSecurityService");
        assertThat(security).contains("public ResponseEntity<Void> setInitialPin() {");
    }

    @Test
    void factorEnrollmentStartsAtTheStepUpAndNotAtASetupStep() throws IOException {
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));

        for (String method : new String[] {
                "public ResponseEntity<PasskeyEnrollStartResponse> startPasskeyEnrollment(",
                "public ResponseEntity<PinEnrollStartResponse> startPinEnrollment(" }) {
            String body = methodBody(security, method);
            assertThat(body).as("%s hands out a session, never a phase", method)
                    .doesNotContain("Phase.PASSKEY_SETUP")
                    .doesNotContain("Phase.PIN_SETUP");
            assertThat(body).contains("startFactorEnrollment(");
        }

        String builder = methodBody(security, "private String startFactorEnrollment(");
        assertThat(builder).contains("session.setPhase(Phase.ENROLL_STEP_UP)");
        assertThat(builder).doesNotContain("Phase.PASSKEY_SETUP");
        assertThat(builder).doesNotContain("Phase.PIN_SETUP");
        assertThat(builder).doesNotContain("setEnrollStepUpFactor");
        assertThat(builder).doesNotContain("setAuthenticatedFactor");
    }

    @Test
    void anEnrollmentStoresNoFactorBeforeTheStepUp() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String accept = methodBody(source, "private ResponseEntity<LoginStateResponse> acceptEnrollStepUp(");
        assertThat(accept).contains("session.setEnrollStepUpFactor(provedWith)");
        assertThat(accept).contains("Phase.PIN_SETUP");
        assertThat(accept).contains("Phase.PASSKEY_SETUP");
        assertThat(accept).doesNotContain("setAuthenticatedFactor");

        String guard = methodBody(source, "private void requireEnrollStepUpDone(");
        assertThat(guard).contains("session.isEnroll() && session.getEnrollStepUpFactor() == null");
        assertThat(guard).contains("StepUpRequiredException");

        for (String method : new String[] {
                "public ResponseEntity<PasskeyOptionsResponse> startPasskeyRegistration(",
                "public ResponseEntity<LoginStateResponse> finishPasskeyRegistration(",
                "public ResponseEntity<LoginStateResponse> submitPinSetup(" }) {
            assertThat(methodBody(source, method)).as("step-up check in %s", method)
                    .contains("requireEnrollStepUpDone(session)");
        }
    }

    @Test
    void theSmsStepUpIsOnlyForAnAccountThatHoldsNoFactor() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String guard = methodBody(source, "private void requireNoStrongerFactor(");
        assertThat(guard).contains("authFactorPolicy.loginPolicy(session.getUserId()).factorSetupRequired()");
        assertThat(guard).contains("\"step_up_factor_available\"");

        for (String method : new String[] {
                "public ResponseEntity<LoginStateResponse> sendEnrollStepUpOtp(",
                "public ResponseEntity<LoginStateResponse> verifyEnrollStepUpOtp(" }) {
            String body = methodBody(source, method);
            assertThat(body).as("factor check in %s", method).contains("requireNoStrongerFactor(session)");
            assertThat(body).contains("accountReauthService.");
        }
    }

    @Test
    void anEnrollmentSessionNeverIssuesAnAuthorizationCode() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String completeEnrollment = methodBody(source,
                "private ResponseEntity<LoginStateResponse> completeEnrollment(");
        assertThat(completeEnrollment).doesNotContain("issueCode");
        assertThat(completeEnrollment).doesNotContain("authorizationService");
        assertThat(completeEnrollment).doesNotContain("recordSuccessfulLogin");

        for (String method : new String[] {
                "public ResponseEntity<LoginStateResponse> finishPasskeyRegistration(",
                "public ResponseEntity<LoginStateResponse> skipPasskeySetup(",
                "public ResponseEntity<LoginStateResponse> submitPinSetup(" }) {
            String body = methodBody(source, method);
            int branch = body.indexOf("session.isEnroll()");
            assertThat(branch).as("enrollment branch in %s", method).isPositive();
            assertThat(body.indexOf("completeEnrollment(sessionId, session)")).as("in %s", method)
                    .isGreaterThan(branch);
        }
    }

    @Test
    void anEnrollmentSessionNeverTouchesAccountGenesis() throws IOException {
        String login = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));

        assertThat(security).as("the enrollment entry points know nothing about genesis")
                .doesNotContain("enesis");

        for (String method : new String[] {
                "public ResponseEntity<PasskeyOptionsResponse> startEnrollStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> finishEnrollStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> submitEnrollStepUpPin(",
                "public ResponseEntity<LoginStateResponse> sendEnrollStepUpOtp(",
                "public ResponseEntity<LoginStateResponse> verifyEnrollStepUpOtp(",
                "private ResponseEntity<LoginStateResponse> acceptEnrollStepUp(",
                "private ResponseEntity<LoginStateResponse> completeEnrollment(" }) {
            assertThat(methodBody(login, method)).as("genesis in %s", method)
                    .doesNotContain("enesis")
                    .doesNotContain("ADOPT_ROOT");
        }
    }

    @Test
    void anEnrollmentSessionNeverSatisfiesRecovery() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        int phases = source.indexOf("RECOVERY_PHASES = ");
        assertThat(phases).isPositive();
        assertThat(source.substring(phases, source.indexOf(";", phases))).doesNotContain("ENROLL_STEP_UP");

        assertThat(methodBody(source, "private boolean recoveryAvailable(")).contains("!session.isEnroll()");
    }

    @Test
    void theLoginStateReportsFactorsOnlyFromPhasesThatHaveResolvedTheSubject() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        int allowList = source.indexOf("FACTOR_REPORT_PHASES =");
        assertThat(allowList).isPositive();
        String declaration = source.substring(allowList, source.indexOf(";", allowList));

        assertThat(declaration).doesNotContain("Phase.PHONE");
        assertThat(declaration).doesNotContain("Phase.OTP_SENT");
        assertThat(declaration).contains("Phase.PIN_REQUIRED");
        assertThat(declaration).contains("Phase.PASSKEY_REQUIRED");

        String publishable = methodBody(source, "private AuthFactorPolicy.RegisteredFactors publishableFactors(");
        assertThat(publishable).contains("FACTOR_REPORT_PHASES.contains(session.getPhase())");
        assertThat(publishable).contains("StringUtils.hasText(session.getUserId())");
        assertThat(publishable).contains("session.getUserId()");
        assertThat(publishable).doesNotContain("getPhoneNumber");
    }

    @Test
    void theBearerFactorReportIsKeyedOnlyByTheAuthenticatedSubject() throws IOException {
        String source = read(MAIN.resolve("controller/security/SecurityController.java"));

        assertThat(source).contains("@GetMapping(\"/pin/status\")");
        assertThat(source).contains("public ResponseEntity<PinStatusResponse> pinStatus() {");

        String pinStatus = methodBody(source, "public ResponseEntity<PinStatusResponse> pinStatus() {");
        assertThat(pinStatus).contains("authenticatedUserAccessor.requireCurrentUserId()");
        assertThat(pinStatus).doesNotContain("request.");
        assertThat(pinStatus).doesNotContain("@RequestParam");
        assertThat(pinStatus).doesNotContain("@PathVariable");
    }

    @Test
    void aCallerNamedEnrollmentRedirectReachesASessionOnlyThroughTheAllowlist() throws IOException {
        String source = read(MAIN.resolve("controller/security/SecurityController.java"));

        String resolver = methodBody(source, "private String enrollRedirectUri(");
        assertThat(resolver).contains("allowlisted(requestedRedirectUri)");
        assertThat(resolver).contains("clientRegisteredAppScheme()");
        assertThat(resolver).contains("loginProperties.getEnroll().getRedirectUri()");

        String allowlisted = methodBody(source, "private String allowlisted(");
        assertThat(allowlisted).contains("loginProperties.getEnroll().allowedRedirectUris()");
        assertThat(allowlisted).contains("invalid_redirect_uri");
        assertThat(allowlisted).contains("requested::equals");
        assertThat(allowlisted).doesNotContain("return requested");
        assertThat(allowlisted).doesNotContain("+ requested");
        assertThat(allowlisted).doesNotContain("requested +");
        assertThat(allowlisted).doesNotContain("requestedRedirectUri +");

        String builder = methodBody(source, "private String startFactorEnrollment(");
        assertThat(builder).contains("String redirectUri = enrollRedirectUri(requestedRedirectUri);");
        assertThat(builder).contains("session.setRedirectUri(redirectUri);");
        assertThat(source.split("setRedirectUri\\(", -1)).hasSize(2);

        assertThat(methodBody(source, "private static String requestedRedirectUri("))
                .contains("request.getRedirectUri()");
        String body = read(MAIN.resolve("controller/dto/FactorEnrollStartRequest.java"));
        assertThat(body.split("\\n    private ", -1)).hasSize(2);
        assertThat(body).contains("private String redirectUri;");
    }

    @Test
    void theSignInAssertionReachesThePinStepAndNeverTheProfileStep() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String phases = methodBody(source, "private void requireAssertionPhase(");

        assertThat(phases).contains("Phase.PIN_REQUIRED");
        assertThat(phases).contains("Phase.PASSKEY_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PROFILE_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PASSKEY_SETUP");
    }

    @Test
    void anEnrollmentSessionIsRefusedTheSignInCeremonyByName() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        assertThat(methodBody(source, "public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication("))
                .contains("refuseEnrollmentSignIn(session)");
        assertThat(methodBody(source, "public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication("))
                .contains("refuseEnrollmentSignIn(session)");
        assertThat(methodBody(source, "private void refuseEnrollmentSignIn(")).contains("session.isEnroll()");
    }

    @Test
    void signupOffersThePasskeyFirstAndKeepsThePinStepReachable() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String profile = methodBody(source, "public ResponseEntity<LoginStateResponse> submitProfile(");
        assertThat(profile).contains("offerPasskeyBeforePin(sessionId, session)");
        assertThat(profile).doesNotContain("Phase.PIN_SETUP");

        String offer = methodBody(source, "private ResponseEntity<LoginStateResponse> offerPasskeyBeforePin(");
        assertThat(offer).contains("authFactorPolicy.passkeysSupported()");
        assertThat(offer).contains("advanceToPinSetup(sessionId, session)");
        assertThat(offer).contains("Phase.PASSKEY_SETUP");

        String skip = methodBody(source, "public ResponseEntity<LoginStateResponse> skipPasskeySetup(");
        int factorCheck = skip.indexOf("session.getAuthenticatedFactor() != null");
        assertThat(factorCheck).isPositive();
        assertThat(skip.indexOf("return complete(sessionId, session)")).isGreaterThan(factorCheck);
        assertThat(skip.indexOf("return advanceToPinSetup(sessionId, session)"))
                .isGreaterThan(skip.indexOf("return complete(sessionId, session)"));

        String pinSetup = methodBody(source, "public ResponseEntity<LoginStateResponse> submitPinSetup(");
        assertThat(pinSetup).contains("request.skip() || !StringUtils.hasText(request.pin())");
        assertThat(pinSetup.indexOf("\"pin_required\"")).isPositive()
                .isLessThan(pinSetup.indexOf("loginFactorEnrollmentService.setUpFirstPin("));
        assertThat(pinSetup).doesNotContain("advanceToPasskeySetup");
        assertThat(pinSetup).contains("complete(sessionId, session)");
    }

    @Test
    void everyStateChangingLoginStepStillChecksTheCsrfToken() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        for (String method : new String[] {
                "public ResponseEntity<LoginStateResponse> submitPhone(",
                "public ResponseEntity<LoginStateResponse> submitOtp(",
                "public ResponseEntity<LoginStateResponse> submitPin(",
                "public ResponseEntity<LoginStateResponse> finishPasskeyRegistration(",
                "public ResponseEntity<LoginStateResponse> startRecovery(",
                "public ResponseEntity<LoginStateResponse> completeRecovery(",
                "public ResponseEntity<LoginStateResponse> submitProfile(",
                "public ResponseEntity<LoginStateResponse> submitPinSetup(",
                "public ResponseEntity<LoginStateResponse> skipPasskeySetup(",
                "public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication(",
                "public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication(",
                "public ResponseEntity<PasskeyOptionsResponse> startEnrollStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> finishEnrollStepUpPasskey(",
                "public ResponseEntity<LoginStateResponse> submitEnrollStepUpPin(",
                "public ResponseEntity<LoginStateResponse> sendEnrollStepUpOtp(",
                "public ResponseEntity<LoginStateResponse> verifyEnrollStepUpOtp(" }) {
            assertThat(methodBody(source, method)).as("CSRF check in %s", method).contains("requireCsrf(session, csrf)");
        }
    }

    @Test
    void completionRefusesASessionThatHasNotAuthenticatedWithAFactor() throws IOException {
        String complete = methodBody(read(MAIN.resolve("controller/oidc/LoginFlowController.java")),
                "private ResponseEntity<LoginStateResponse> complete(");

        int guard = complete.indexOf("session.getAuthenticatedFactor() == null");
        assertThat(guard).isPositive();
        assertThat(complete.indexOf("\"factor_required\"")).isGreaterThan(guard);
        assertThat(complete.indexOf("recordSuccessfulLogin")).isGreaterThan(guard);
        assertThat(complete.indexOf("issueCode")).isGreaterThan(guard);
    }

    @Test
    void theEndOtherSessionsMarkerIsOnlyEverSetForARecovery() throws IOException {
        String login = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String tokens = read(MAIN.resolve("service/oidc/OidcTokenService.java"));

        assertThat(login).containsOnlyOnce("setAuthenticatedFactor(SessionFactor.RECOVERY)");
        assertThat(methodBody(login, "public ResponseEntity<LoginStateResponse> completeRecovery("))
                .contains("setAuthenticatedFactor(SessionFactor.RECOVERY)");
        assertThat(methodBody(login, "private ResponseEntity<LoginStateResponse> complete("))
                .contains("session.getAuthenticatedFactor() == SessionFactor.RECOVERY");
        assertThat(tokens).containsOnlyOnce("END_OTHER_SESSIONS_CLAIM, true");
        assertThat(tokens).contains("authorization.endOtherSessions()");

        try (var sources = Files.walk(MAIN)) {
            for (Path file : sources.filter(path -> path.toString().endsWith(".java")).toList()) {
                String source = read(file);
                if (file.endsWith(Path.of("service/security/AccountRecoveryService.java"))) {
                    assertThat(source).containsOnlyOnce("endOtherSessionsService.markOwed(");
                    assertThat(methodBody(source, "public int complete(")).contains("endOtherSessionsService.markOwed(");
                } else if (!file.endsWith(Path.of("service/security/EndOtherSessionsService.java"))) {
                    assertThat(source).as(file.toString()).doesNotContain(".markOwed(");
                }
                if (!file.endsWith(Path.of("service/oidc/OidcTokenService.java"))
                        && !file.endsWith(Path.of("service/security/EndOtherSessionsService.java"))) {
                    assertThat(source).as(file.toString()).doesNotContain("endOtherSessionsService.settle(");
                }
            }
        }
    }

    @Test
    void signInRoutingReadsTheStoredCredentialNotTheDeploymentSwitch() throws IOException {
        String policy = methodBody(read(MAIN.resolve("service/security/AuthFactorPolicy.java")),
                "public LoginPolicy loginPolicy(");
        String login = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String orchestration = read(MAIN.resolve("service/IdentityOrchestrationService.java"));

        assertThat(policy).contains("passkeyHeld(userId)");
        assertThat(policy).doesNotContain("passkeyRegistered");
        assertThat(methodBody(login, "private ResponseEntity<LoginStateResponse> routeExistingUser("))
                .contains("authFactorPolicy.loginPolicy(userId)")
                .doesNotContain("passkeyRegistered");
        assertThat(methodBody(login, "private ResponseEntity<LoginStateResponse> advanceToPasskeySetup("))
                .doesNotContain("passkeyRegistered");
        assertThat(orchestration).doesNotContain("passkeyRegistered");
    }

    @Test
    void recoveryIsOfferedOnlyAfterAnOtpInASignIn() throws IOException {
        String login = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        assertThat(login).containsOnlyOnce("setOtpVerified(true)");
        assertThat(methodBody(login, "public ResponseEntity<LoginStateResponse> submitOtp("))
                .contains("setOtpVerified(true)");
        String available = methodBody(login, "private boolean recoveryAvailable(");
        assertThat(available).contains("session.isOtpVerified()");
        assertThat(available).contains("session.getReauthUserId() == null");
        assertThat(available).contains("!session.isEnroll()");
        assertThat(available).contains("RECOVERY_PHASES.contains(session.getPhase())");
        for (String endpoint : new String[] {
                "public ResponseEntity<LoginStateResponse> startRecovery(",
                "public ResponseEntity<LoginStateResponse> completeRecovery(" }) {
            assertThat(methodBody(login, endpoint)).contains("requireRecoveryAvailable(session)");
        }
    }

    @Test
    void everyRecoveryWriterTakesTheRowLock() throws IOException {
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));

        assertThat(methodBody(recovery, "public AccountRecoveryState start(")).contains("lockOrCreateUser(userId)");
        assertThat(methodBody(recovery, "public int complete(")).contains("lockUser(userId)");
        assertThat(methodBody(recovery, "public boolean cancel(")).contains("lockUser(userId)");
        for (String writer : new String[] { "public AccountRecoveryState start(", "public int complete(",
                "public boolean cancel(" }) {
            assertThat(methodBody(recovery, writer)).doesNotContain("findUser(");
        }
        assertThat(methodBody(userSecurity, "public void recordSuccessfulLogin(")).contains("lockOrCreateUser(userId)");
        assertThat(methodBody(userSecurity, "public void validatePinOrThrow(")).contains("findByUserIdForUpdate");
        assertThat(methodBody(userSecurity, "IdentityUser lockOrCreateUser(")).contains("findByUserIdForUpdate");
    }

    @Test
    void theRetiredPinResetDoesNothingButRefuse() throws IOException {
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));
        String config = read(MAIN.resolve("config/SecurityConfig.java"));

        String retired = methodBody(security, "public ResponseEntity<Void> retiredPinReset(");
        assertThat(retired).contains("throw new EndpointRetiredException(");
        assertThat(retired).doesNotContain("Service.");
        assertThat(security).contains("public ResponseEntity<Void> retiredPinReset() {");
        int open = config.indexOf("OPEN_POST_ENDPOINTS = List.of(");
        assertThat(config.substring(open, config.indexOf(");", open))).doesNotContain("/security/pin/reset");
    }

    /** Brace-counted, skipping double-quoted strings, so assertions never run over a truncated fragment. */
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
