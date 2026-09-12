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
     */
    @Test
    void theStepUpPathChecksTheUserVerifiedFlagOnTheAssertionItself() throws IOException {
        String source = read(MAIN.resolve("service/security/PasskeyService.java"));

        assertThat(source).contains("result.isUserVerified()");
        assertThat(source).contains("requireUserVerification");
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
     * Returns the source of one method, from its signature to the first line that closes at
     * method indentation, so ordering assertions cannot accidentally match text elsewhere in
     * the file.
     */
    private static String methodBody(String source, String signature) {
        int start = source.indexOf(signature);
        assertThat(start).as("method %s", signature).isPositive();
        int end = source.indexOf("\n    }", start);
        assertThat(end).as("end of method %s", signature).isGreaterThan(start);
        return source.substring(start, end);
    }

    private static String read(Path path) throws IOException {
        return Files.readString(path);
    }
}
