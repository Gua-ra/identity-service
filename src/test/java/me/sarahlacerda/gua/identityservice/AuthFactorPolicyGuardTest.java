package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/**
 * Freezes the decisions behind the step-up bar and the OTP namespacing, because each of
 * them is one plausible-looking edit away from either a bypass or a lockout and none of
 * them is visible in the behaviour of a single method.
 */
class AuthFactorPolicyGuardTest {

    private static final Path MAIN = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice");

    /**
     * The step-up bar is read off the assertion that was actually presented. A ceremony
     * that asked for user verification is not the same thing as a response that performed
     * it, and the stored request is attacker-adjacent state.
     *
     * <p>
     * Scoped to the method that redeems an assertion, because a match anywhere in the file
     * was not a guard at all: those two strings also appear in comments and in the ceremony
     * builders, so every way of switching the check off left them sitting there and this test
     * went on passing. What holds the bar now is behaviour, in
     * {@code PasskeyServiceStepUpTest}: an assertion whose {@code isUserVerified()} is false
     * is refused for a step-up and still accepted for a sign-in. This test is the narrower
     * claim that survives being a text match, which is that the flag is read off the response
     * in the one place where reading it off the stored request instead would mean something.
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
     * Deliberate non-change. A counter that legitimately never moves is normal for a
     * passkey held in a synced credential manager, so validating it would lock those
     * accounts out of their own credential, and the counter is not what the step-up bar
     * rests on.
     */
    @Test
    void signatureCounterValidationStaysOff() throws IOException {
        String source = read(MAIN.resolve("service/security/PasskeyService.java"));

        assertThat(source).contains("validateSignatureCounter(false)");
    }

    /**
     * Sign-in keeps the lower bar. Raising it would refuse an authenticator that cannot
     * verify a user and push those accounts onto another factor, for no gain: sign-in is
     * not where an assertion stands in for a knowledge factor.
     */
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
     * Neither PIN flow may verify against the per-phone key the unauthenticated public
     * send writes. Both go through the scoped API, which keys the code to the flow.
     */
    @Test
    void thePinFlowsDoNotVerifyAgainstThePerPhoneOtpKey() throws IOException {
        String source = read(MAIN.resolve("service/security/UserSecurityService.java"));

        assertThat(source).doesNotContain("otpService.sendOtp(");
        assertThat(source).doesNotContain("otpService.verifyOtp(");
        assertThat(source).contains("OtpScope.PIN_CHANGE");
        assertThat(source).contains("OtpScope.PIN_RESET");
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
        assertThat(source).containsOnlyOnce("private void verify(String codeKey, String attemptsKey, String code)");
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
     * Precedence, frozen as source order because that is where it lives. Reordering these
     * branches is a one-line edit that no single method's behaviour makes obvious, and each
     * possible order fails differently: the PIN first makes the stronger factor pointless,
     * the refusal first locks everyone out.
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
        // Demoted below the passkey, never deleted: it is the only thing that keeps a
        // credential that has become unusable from being an account that cannot be used.
        assertThat(pinBranch).isGreaterThan(passkeyBranch);
        // And the refusal is last, so neither branch can fall past it into a token-only path.
        assertThat(hardBlock).isGreaterThan(pinBranch);
    }

    /**
     * The step-up never asks whether the account HAS a passkey, only whether this caller
     * produced one. The existence check carries no signal about whether the credential can be
     * used on the device in front of the user, so requiring it, or skipping a factor because
     * of it, converts a broken credential into a closed account.
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
     * No self-attested downgrade. A field saying which factors the caller cannot use would be
     * free for anyone holding a session to set, so it could only ever be a request for the
     * weaker factor. The natural shape for one is a boolean on the step-up request.
     */
    @Test
    void theStepUpRequestCarriesNoWayToClaimAFactorIsUnavailable() throws IOException {
        String source = read(MAIN.resolve("controller/dto/PhoneChangeStartRequest.java"));

        assertThat(source).doesNotContain("boolean");
        assertThat(source).doesNotContain("Boolean");
    }

    /**
     * The decision sites delegate rather than each deriving the answer. "Does this account
     * need a PIN step" was decided in three services and "does it already have a passkey" in
     * two controllers, and any one of them could be edited into disagreeing with the others.
     */
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
     * Recovery is not gated on holding a stronger factor, and the service that owns it does
     * not consult passkeys at all. A gate there is permanent lockout, not a bypass fix: the
     * account would have no login and no recovery, and nothing here can remove or replace a
     * registered credential. Closing that hole needs a protocol that can prove the stronger
     * factor is really gone, which does not exist yet.
     */
    @Test
    void pinRecoveryIsNotGatedOnARegisteredPasskey() throws IOException {
        String userSecurity = read(MAIN.resolve("service/security/UserSecurityService.java"));
        String recovery = methodBody(read(MAIN.resolve("service/security/AuthFactorPolicy.java")),
                "public RecoveryPolicy recoveryFor(");

        assertThat(userSecurity).doesNotContain("Passkey");
        assertThat(userSecurity).doesNotContain("passkey");
        // Reported, not branched on: the method hands back what the account holds and refuses
        // nothing.
        assertThat(recovery).doesNotContain("if (");
        assertThat(recovery).doesNotContain("throw ");
    }

    /**
     * Setting a first PIN stays free of any step-up. An account whose passkey stopped working
     * needs to be able to acquire the fallback, and a step-up it cannot satisfy would strand
     * it with a 403 and no way past it.
     */
    @Test
    void settingTheFirstPinDemandsNoStepUp() throws IOException {
        String setInitialPin = methodBody(read(MAIN.resolve("controller/security/SecurityController.java")),
                "public ResponseEntity<Void> setInitialPin(");

        assertThat(setInitialPin).doesNotContain("authFactorPolicy");
        assertThat(setInitialPin).doesNotContain("passkey");
        assertThat(setInitialPin).doesNotContain("stepUp");
    }

    /**
     * The factor report on the interactive login state is allow-listed by phase, and the allow
     * list holds no step that a caller reaches by typing a phone number.
     *
     * <p>
     * Reporting it at the phone or OTP step would be an enumeration oracle: those sessions hold
     * a submitted number and nothing proved, so "does this account hold a passkey" asked there
     * is answerable about anybody, by anybody, for one unverified request. An allow list is the
     * shape that fails safe. Two exclusions would leave a phase added later reporting by default
     * because nobody remembered to add it to the list.
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

        // And the phase alone is not enough: the report is keyed by the subject the session
        // actually resolved, never by the number that was submitted to reach it.
        String publishable = methodBody(source, "private AuthFactorPolicy.RegisteredFactors publishableFactors(");
        assertThat(publishable).contains("FACTOR_REPORT_PHASES.contains(session.getPhase())");
        assertThat(publishable).contains("StringUtils.hasText(session.getUserId())");
        assertThat(publishable).contains("session.getUserId()");
        assertThat(publishable).doesNotContain("getPhoneNumber");
    }

    /**
     * The bearer-gated status endpoint answers for whoever the token says, and takes nothing
     * from the caller to key it by. The same report behind a submitted identifier would be the
     * same oracle in a different place.
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
     * The sign-in assertion reaches the PIN step, which is where the people who would most want
     * it end up, and never the profile step, which belongs to a session that matched no account.
     * An assertion accepted there would be an assertion reaching account creation.
     */
    @Test
    void theSignInAssertionReachesThePinStepAndNeverTheProfileStep() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));
        String phases = methodBody(source, "private void requireAssertionPhase(");

        assertThat(phases).contains("Phase.PIN_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PROFILE_REQUIRED");
        assertThat(phases).doesNotContain("Phase.PASSKEY_SETUP");
    }

    /**
     * An enrollment session carries no OIDC request and so has no authorization code to issue.
     * It is kept out of the sign-in ceremony by name, not only by which step it happens to be
     * sitting on, so widening the phase set again cannot quietly turn one into a login.
     */
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
     * Signup order: the passkey is offered first and the PIN step is what a new account falls
     * back to. The PIN must stay REACHABLE, because a device with no usable authenticator would
     * otherwise finish onboarding holding nothing, so the fallback edge is asserted as
     * explicitly as the order is.
     */
    @Test
    void signupOffersThePasskeyFirstAndKeepsThePinStepReachable() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        // The profile step no longer names the PIN at all: it hands over to the routing below.
        String profile = methodBody(source, "public ResponseEntity<LoginStateResponse> submitProfile(");
        assertThat(profile).contains("offerPasskeyBeforePin(sessionId, session)");
        assertThat(profile).doesNotContain("Phase.PIN_SETUP");

        // Which offers the passkey, and falls back to the PIN step on a deployment that has no
        // passkeys to offer. That condition is read from configuration, never from the request.
        String offer = methodBody(source, "private ResponseEntity<LoginStateResponse> offerPasskeyBeforePin(");
        assertThat(offer).contains("authFactorPolicy.passkeysSupported()");
        assertThat(offer).contains("advanceToPinSetup(sessionId, session)");
        assertThat(offer).contains("Phase.PASSKEY_SETUP");

        // Leaving the offer without a credential sends a new account to the PIN step, not to the
        // end of the flow. Declined, failed and impossible all arrive at this one endpoint.
        String skip = methodBody(source, "public ResponseEntity<LoginStateResponse> skipPasskeySetup(");
        assertThat(skip.indexOf("advanceToPinSetup(sessionId, session)"))
                .isGreaterThan(0)
                .isLessThan(skip.indexOf("return complete(sessionId, session)"));
        assertThat(skip).contains("session.isNewUser()");

        // And the PIN step is the end of signup, so it cannot route back to the offer it was
        // reached from.
        String pinSetup = methodBody(source, "public ResponseEntity<LoginStateResponse> submitPinSetup(");
        assertThat(pinSetup).doesNotContain("advanceToPasskeySetup");
        assertThat(pinSetup).contains("complete(sessionId, session)");
    }

    /**
     * Every state-changing step still carries the double-submit check. The flow was reordered,
     * not loosened, and a step that quietly lost its CSRF check would be reachable from any
     * page the user's browser can be made to load.
     */
    @Test
    void everyStateChangingLoginStepStillChecksTheCsrfToken() throws IOException {
        String source = read(MAIN.resolve("controller/oidc/LoginFlowController.java"));

        for (String method : new String[] {
                "public ResponseEntity<LoginStateResponse> submitProfile(",
                "public ResponseEntity<LoginStateResponse> submitPinSetup(",
                "public ResponseEntity<LoginStateResponse> skipPasskeySetup(",
                "public ResponseEntity<PasskeyOptionsResponse> startPasskeyAuthentication(",
                "public ResponseEntity<LoginStateResponse> finishPasskeyAuthentication(" }) {
            assertThat(methodBody(source, method)).as("CSRF check in %s", method).contains("requireCsrf(session, csrf)");
        }
    }

    /**
     * Returns the source of one method, from its signature to the first line that closes at
     * method indentation, so ordering assertions cannot accidentally match text elsewhere in
     * the file.
     */
    /**
     * The body of a named method, from its signature to its matching closing brace.
     *
     * <p>
     * Brace-counted rather than cut at the first line closing at four spaces. The cheap
     * version returned a fragment the moment a method grew an inner block that closed at that
     * indentation, and every {@code doesNotContain} over a fragment passes for the wrong
     * reason: the text is absent because the method was truncated, not because the code is
     * not there. Double-quoted strings are skipped so a brace inside a log format or a
     * message cannot unbalance the count.
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
