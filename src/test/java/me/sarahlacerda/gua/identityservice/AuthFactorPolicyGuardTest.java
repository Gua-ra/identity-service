package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/**
 * Source-text guards for the step-up bar, the OTP namespacing, the sign-in factor gate and the
 * delayed account recovery. Each is one plausible edit away from a bypass or a lockout, and none is
 * visible in the behaviour of a single method.
 */
class AuthFactorPolicyGuardTest {

    private static final Path MAIN = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice");

    /**
     * The step-up bar is read off the assertion that was presented, not off what the stored ceremony
     * asked for. Scoped to the method that redeems an assertion; the behaviour is pinned by
     * {@code PasskeyServiceStepUpTest}.
     */
    @Test
    void theStepUpPathChecksTheUserVerifiedFlagOnTheAssertionItself() throws IOException {
        String redeem = methodBody(read(MAIN.resolve("service/security/PasskeyService.java")),
                "private PasskeyAuthentication redeemAssertion(");

        assertThat(redeem).contains("requireUserVerification && !result.isUserVerified()");
        // Never from what the stored ceremony asked for: that is the caller's request, not
        // the authenticator's report of what it did.
        assertThat(redeem).doesNotContain("UserVerificationRequirement");
    }

    /**
     * Deliberately not validated: a counter that never moves is normal for a passkey held in a synced
     * credential manager, so validating it would lock those accounts out.
     */
    @Test
    void signatureCounterValidationStaysOff() throws IOException {
        String source = read(MAIN.resolve("service/security/PasskeyService.java"));

        assertThat(source).contains("validateSignatureCounter(false)");
    }

    /** Sign-in keeps the lower bar: raising it would refuse an authenticator that cannot verify a user. */
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

    /**
     * The PIN change may not verify against the per-phone key the unauthenticated public send writes;
     * it goes through the scoped API. The account recovery sends no code at all.
     */
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

    /**
     * The scoped verify shares the per-code guess cap with the public one. A namespaced
     * code with no cap behind it would trade one weakness for another.
     */
    @Test
    void theScopedOtpPathSharesTheCappedVerify() throws IOException {
        String source = read(MAIN.resolve("service/OtpService.java"));

        assertThat(source).contains("verifyScopedOtp");
        // One implementation, so the cap cannot be present on one path and absent on the other.
        assertThat(source)
                .containsOnlyOnce("private void verify(String codeKey, String attemptsKey, String code, OtpVerifyFlow flow)");
        assertThat(source).containsOnlyOnce("countGuess(codeKey, attemptsKey)");
    }

    /**
     * The hard block and the ownership check are the two things the step-up must never
     * lose, whatever order the factors are tried in.
     */
    @Test
    void thePhoneChangeStepUpKeepsItsHardBlockAndItsOwnershipCheck() throws IOException {
        String source = read(MAIN.resolve("service/security/PhoneChangeService.java"));

        assertThat(source).contains("throw new StepUpRequiredException(");
        assertThat(source).contains("Passkey does not belong to the calling account");
        // The PIN branch stays a branch: an account with a PIN and no passkey keeps a way through.
        assertThat(source).contains("if (hasPin) {");
    }

    /**
     * Precedence, frozen as source order. Each wrong order fails differently: the PIN first makes the
     * stronger factor pointless, the refusal first locks everyone out.
     */
    @Test
    void theStepUpTriesThePasskeyFirstThenThePinThenRefuses() throws IOException {
        String stepUp = methodBody(read(MAIN.resolve("service/security/PhoneChangeService.java")),
                "private void enforceStepUp(");

        int passkeyBranch = stepUp.indexOf("if (passkeyAttempted) {");
        int ownership = stepUp.indexOf("Passkey does not belong to the calling account");
        int pinBranch = stepUp.indexOf("if (hasPin) {");
        int hardBlock = stepUp.indexOf("throw new StepUpRequiredException(");

        assertThat(passkeyBranch).isPositive();
        // The ownership check sits inside the passkey branch, ahead of the point where the
        // assertion is treated as accepted.
        assertThat(ownership).isGreaterThan(passkeyBranch).isLessThan(pinBranch);
        // The PIN branch sits below the passkey and is never deleted.
        assertThat(pinBranch).isGreaterThan(passkeyBranch);
        // And the refusal is last, so neither branch can fall past it into a token-only path.
        assertThat(hardBlock).isGreaterThan(pinBranch);
    }

    /**
     * The step-up never asks whether the account has a passkey, only whether this caller produced one.
     * Requiring one because it exists would turn a broken credential into a closed account.
     */
    @Test
    void theStepUpNeverConsultsPasskeyRegistration() throws IOException {
        String source = read(MAIN.resolve("service/security/PhoneChangeService.java"));

        assertThat(source).doesNotContain("hasPasskey");
        assertThat(source).doesNotContain("passkeyRegistered");
    }

    /**
     * A challenge is spent by being presented, not by being accepted. One that survived a
     * refusal could be presented again for the rest of its TTL, which makes a failed attempt
     * free.
     */
    @Test
    void theAssertionChallengeIsBurnedOnRefusalAsWellAsOnAcceptance() throws IOException {
        String redeem = methodBody(read(MAIN.resolve("service/security/PasskeyService.java")),
                "private PasskeyAuthentication redeemAssertion(");

        int finallyBlock = redeem.indexOf("} finally {");
        assertThat(finallyBlock).isPositive();
        // In the finally, so no branch added later can return or throw past it.
        assertThat(redeem.indexOf("redisTemplate.delete(challengeKey)")).isGreaterThan(finallyBlock);
    }

    /**
     * No self-attested downgrade: a field saying which factors the caller cannot use could only be a
     * request for the weaker factor.
     */
    @Test
    void theStepUpRequestCarriesNoWayToClaimAFactorIsUnavailable() throws IOException {
        String source = read(MAIN.resolve("controller/dto/PhoneChangeStartRequest.java"));

        assertThat(source).doesNotContain("boolean");
        assertThat(source).doesNotContain("Boolean");
    }

    /** The decision sites delegate to AuthFactorPolicy instead of each deriving the answer. */
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

    /**
     * Recovery is not gated on holding a stronger factor: an account whose passkey broke would then
     * have no way back. Recovery removes passkeys on completion, which is not a gate. The service that
     * holds the PIN primitives does not consult passkeys at all.
     */
    @Test
    void recoveryIsNotGatedOnHoldingAPasskey() throws IOException {
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String policy = methodBody(read(MAIN.resolve("service/security/AuthFactorPolicy.java")),
                "public RecoveryPolicy recoveryFor(");
        String recovery = read(MAIN.resolve("service/security/AccountRecoveryService.java"));

        assertThat(userSecurity).doesNotContain("Passkey");
        assertThat(userSecurity).doesNotContain("passkey");
        // Reported, not branched on.
        assertThat(policy).doesNotContain("if (");
        assertThat(policy).doesNotContain("throw ");
        // No status, start or completion asks what the account holds.
        assertThat(recovery).doesNotContain("hasPasskey");
        assertThat(recovery).doesNotContain("passkeyHeld");
        assertThat(recovery).doesNotContain("passkeyRegistered");
        assertThat(recovery).doesNotContain("hasPin");
        // The passkeys are removed inside the completing transaction.
        assertThat(methodBody(recovery, "public int complete(")).contains("passkeyService.removeAllForUser(userId)");
    }

    /**
     * Setting a first PIN from a bearer session alone is retired: a PIN set from a session is a second
     * way in that outlives the session. The handler takes no body and touches nothing, so an older
     * client is told where to go.
     */
    @Test
    void theBearerFirstPinIsRetiredInFavourOfTheEnrollmentStepUp() throws IOException {
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));
        String setInitialPin = methodBody(security, "public ResponseEntity<Void> setInitialPin(");

        assertThat(setInitialPin).contains("throw new StepUpRequiredException(");
        assertThat(setInitialPin).contains("/security/pin/enroll/start");
        assertThat(setInitialPin).doesNotContain("userSecurityService");
        // No parameters at all, so no body is read and no validation runs before the refusal.
        assertThat(security).contains("public ResponseEntity<Void> setInitialPin() {");
    }

    /**
     * Both enrollment entry points park at the step-up, and neither drops a session straight into a
     * step that stores a factor.
     */
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
        // Nothing is proved yet, so nothing may be recorded as proved.
        assertThat(builder).doesNotContain("setEnrollStepUpFactor");
        assertThat(builder).doesNotContain("setAuthenticatedFactor");
    }

    /**
     * Only the step-up moves an enrollment session to a step that stores a factor, and the steps that
     * store one refuse a session that has not been through it.
     */
    @Test
    void anEnrollmentStoresNoFactorBeforeTheStepUp() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String accept = methodBody(source, "private ResponseEntity<LoginStateResponse> acceptEnrollStepUp(");
        assertThat(accept).contains("session.setEnrollStepUpFactor(provedWith)");
        assertThat(accept).contains("Phase.PIN_SETUP");
        assertThat(accept).contains("Phase.PASSKEY_SETUP");
        // An enrollment must not become a session that can finish a sign-in.
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

    /**
     * The SMS proof is confined to an account that holds no factor at all. Anywhere else it would let
     * a code sent to the number stand in for the factor the account already has.
     */
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
            // And the number is checked by the one component that compares it with the account's
            // own directory binding, rather than being trusted or looked up here.
            assertThat(body).contains("accountReauthService.");
        }
    }

    /** An enrollment session issues no authorization code, whatever step it finishes at. */
    @Test
    void anEnrollmentSessionNeverIssuesAnAuthorizationCode() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        String completeEnrollment = methodBody(source,
                "private ResponseEntity<LoginStateResponse> completeEnrollment(");
        assertThat(completeEnrollment).doesNotContain("issueCode");
        assertThat(completeEnrollment).doesNotContain("authorizationService");
        assertThat(completeEnrollment).doesNotContain("recordSuccessfulLogin");

        // Every terminal step an enrollment can reach branches to it before the login completion.
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

    /** An enrollment touches no account genesis and no account-authority transition. */
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

    /**
     * An enrollment session cannot satisfy a recovery: it belongs to someone already signed in, and
     * letting it count would turn a held session into a way to take the account.
     */
    @Test
    void anEnrollmentSessionNeverSatisfiesRecovery() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        int phases = source.indexOf("RECOVERY_PHASES = ");
        assertThat(phases).isPositive();
        assertThat(source.substring(phases, source.indexOf(";", phases))).doesNotContain("ENROLL_STEP_UP");

        assertThat(methodBody(source, "private boolean recoveryAvailable(")).contains("!session.isEnroll()");
    }

    /**
     * The factor report on the interactive login state is allow-listed by phase, and the allow list
     * holds no step a caller reaches by typing a phone number. Reporting it there would let anyone
     * probe any number.
     */
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

        // And the phase alone is not enough: the report is keyed by the subject the session
        // actually resolved, never by the number that was submitted to reach it.
        String publishable = methodBody(source, "private AuthFactorPolicy.RegisteredFactors publishableFactors(");
        assertThat(publishable).contains("FACTOR_REPORT_PHASES.contains(session.getPhase())");
        assertThat(publishable).contains("StringUtils.hasText(session.getUserId())");
        assertThat(publishable).contains("session.getUserId()");
        assertThat(publishable).doesNotContain("getPhoneNumber");
    }

    /**
     * The bearer-gated status endpoint answers for whoever the token says and takes nothing from the
     * caller to key it by.
     */
    @Test
    void theBearerFactorReportIsKeyedOnlyByTheAuthenticatedSubject() throws IOException {
        String source = read(MAIN.resolve("controller/security/SecurityController.java"));

        // An empty parameter list on a path with no variables: there is nothing submitted for
        // this to be keyed by, which is the assertion.
        assertThat(source).contains("@GetMapping(\"/pin/status\")");
        assertThat(source).contains("public ResponseEntity<PinStatusResponse> pinStatus() {");

        String pinStatus = methodBody(source, "public ResponseEntity<PinStatusResponse> pinStatus() {");
        assertThat(pinStatus).contains("authenticatedUserAccessor.requireCurrentUserId()");
        assertThat(pinStatus).doesNotContain("request.");
        assertThat(pinStatus).doesNotContain("@RequestParam");
        assertThat(pinStatus).doesNotContain("@PathVariable");
    }

    /**
     * A caller-named enrollment redirect reaches a session through the allowlist and no other way. The
     * configured entry, not the submitted string, is what gets stamped. Behaviour is pinned by
     * {@code SecurityControllerTest}; this is the structural half.
     */
    @Test
    void aCallerNamedEnrollmentRedirectReachesASessionOnlyThroughTheAllowlist() throws IOException {
        String source = read(MAIN.resolve("controller/security/SecurityController.java"));

        // The resolution order, in one method: a named value goes to the allowlist, and an
        // absent one never touches it.
        String resolver = methodBody(source, "private String enrollRedirectUri(");
        assertThat(resolver).contains("allowlisted(requestedRedirectUri)");
        assertThat(resolver).contains("clientRegisteredAppScheme()");
        assertThat(resolver).contains("loginProperties.getEnroll().getRedirectUri()");

        // The allowlist is the deployment's, the match is exact, and what comes back is the
        // configured entry rather than the string that arrived.
        String allowlisted = methodBody(source, "private String allowlisted(");
        assertThat(allowlisted).contains("loginProperties.getEnroll().allowedRedirectUris()");
        assertThat(allowlisted).contains("invalid_redirect_uri");
        assertThat(allowlisted).contains("requested::equals");
        assertThat(allowlisted).doesNotContain("return requested");
        // A refused value is not echoed back: the message is a constant, with nothing
        // concatenated onto it.
        assertThat(allowlisted).doesNotContain("+ requested");
        assertThat(allowlisted).doesNotContain("requested +");
        assertThat(allowlisted).doesNotContain("requestedRedirectUri +");

        // One place stamps a session, and it is fed by the resolver and by nothing else.
        String builder = methodBody(source, "private String startFactorEnrollment(");
        assertThat(builder).contains("String redirectUri = enrollRedirectUri(requestedRedirectUri);");
        assertThat(builder).contains("session.setRedirectUri(redirectUri);");
        assertThat(source.split("setRedirectUri\\(", -1)).hasSize(2);

        // And the redirect is the only thing either endpoint reads off the request: the body is
        // one optional field, and nothing else submitted is looked at.
        assertThat(methodBody(source, "private static String requestedRedirectUri("))
                .contains("request.getRedirectUri()");
        String body = read(MAIN.resolve("controller/dto/FactorEnrollStartRequest.java"));
        assertThat(body.split("\\n    private ", -1)).hasSize(2);
        assertThat(body).contains("private String redirectUri;");
    }

    /**
     * The sign-in assertion reaches the PIN step and never the profile step, which belongs to a
     * session that matched no account.
     */
    @Test
    void theSignInAssertionReachesThePinStepAndNeverTheProfileStep() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String phases = methodBody(source, "private void requireAssertionPhase(");

        assertThat(phases).contains("Phase.PIN_REQUIRED");
        assertThat(phases).contains("Phase.PASSKEY_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PROFILE_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PASSKEY_SETUP");
    }

    /** An enrollment session is kept out of the sign-in ceremony by name, not only by its phase. */
    @Test
    void anEnrollmentSessionIsRefusedTheSignInCeremonyByName() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        assertThat(methodBody(source, "public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication("))
                .contains("refuseEnrollmentSignIn(session)");
        assertThat(methodBody(source, "public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication("))
                .contains("refuseEnrollmentSignIn(session)");
        assertThat(methodBody(source, "private void refuseEnrollmentSignIn(")).contains("session.isEnroll()");
    }

    /**
     * Signup order: the passkey is offered first and the PIN step is the fallback. The PIN must stay
     * reachable (a device with no usable authenticator needs a way to get a factor) and mandatory
     * (skipping it would finish the sign-in on the phone OTP alone).
     */
    @Test
    void signupOffersThePasskeyFirstAndKeepsThePinStepReachable() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        // The profile step does not name the PIN: it hands over to the routing below.
        String profile = methodBody(source, "public ResponseEntity<LoginStateResponse> submitProfile(");
        assertThat(profile).contains("offerPasskeyBeforePin(sessionId, session)");
        assertThat(profile).doesNotContain("Phase.PIN_SETUP");

        // Which offers the passkey, and falls back to the PIN step on a deployment that has no
        // passkeys to offer. That condition is read from configuration, never from the request.
        String offer = methodBody(source, "private ResponseEntity<LoginStateResponse> offerPasskeyBeforePin(");
        assertThat(offer).contains("authFactorPolicy.passkeysSupported()");
        assertThat(offer).contains("advanceToPinSetup(sessionId, session)");
        assertThat(offer).contains("Phase.PASSKEY_SETUP");

        // Leaving the offer completes only a session that already authenticated with a factor;
        // everything else goes on to the PIN step. Declined, failed and impossible all arrive here.
        String skip = methodBody(source, "public ResponseEntity<LoginStateResponse> skipPasskeySetup(");
        int factorCheck = skip.indexOf("session.getAuthenticatedFactor() != null");
        assertThat(factorCheck).isPositive();
        assertThat(skip.indexOf("return complete(sessionId, session)")).isGreaterThan(factorCheck);
        assertThat(skip.indexOf("return advanceToPinSetup(sessionId, session)"))
                .isGreaterThan(skip.indexOf("return complete(sessionId, session)"));

        // The PIN step refuses to be skipped or left blank before anything else happens, and it is
        // the end of signup, so it cannot route back to the offer it was reached from.
        String pinSetup = methodBody(source, "public ResponseEntity<LoginStateResponse> submitPinSetup(");
        assertThat(pinSetup).contains("request.skip() || !StringUtils.hasText(request.pin())");
        assertThat(pinSetup.indexOf("\"pin_required\"")).isPositive()
                .isLessThan(pinSetup.indexOf("loginFactorEnrollmentService.setUpFirstPin("));
        assertThat(pinSetup).doesNotContain("advanceToPasskeySetup");
        assertThat(pinSetup).contains("complete(sessionId, session)");
    }

    /** Every state-changing step carries the double-submit CSRF check. */
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

    /**
     * Nothing issues an authorization code to a session that has not authenticated with a factor. The
     * check is the first thing completion does.
     */
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

    /**
     * The claim that makes the authentication service end every other session is set for a completed
     * recovery and nothing else, or for a sign-out a completed recovery still owes.
     */
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

    /**
     * Sign-in routing reads what is stored. Reading the deployment-gated answer would let switching
     * passkeys off turn a passkey-only account into one an SMS code finishes by choosing a PIN.
     */
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

    /**
     * Recovery starts only from a proved phone number, in a real sign-in. The flag is set in one
     * place, the OTP step, and every condition of availability is checked together.
     */
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

    /**
     * Every recovery writer, and every sign-in writer that ends an episode, reads the account row
     * under its lock, so cancel and complete can never both win and a sign-in cannot write back a
     * PIN hash or a stamp another transaction just committed.
     */
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

    /** The unauthenticated PIN reset is retired: its handler takes nothing and touches nothing. */
    @Test
    void theRetiredPinResetDoesNothingButRefuse() throws IOException {
        String security = read(MAIN.resolve("controller/security/SecurityController.java"));
        String config = read(MAIN.resolve("config/SecurityConfig.java"));

        String retired = methodBody(security, "public ResponseEntity<Void> retiredPinReset(");
        assertThat(retired).contains("throw new EndpointRetiredException(");
        assertThat(retired).doesNotContain("Service.");
        // No parameters at all, so no body is read and no validation runs before the refusal.
        assertThat(security).contains("public ResponseEntity<Void> retiredPinReset() {");
        int open = config.indexOf("OPEN_POST_ENDPOINTS = List.of(");
        assertThat(config.substring(open, config.indexOf(");", open))).doesNotContain("/security/pin/reset");
    }

    /**
     * The body of a named method, from its signature to its matching closing brace. Brace-counted, and
     * double-quoted strings are skipped so a brace inside a message cannot unbalance the count.
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
