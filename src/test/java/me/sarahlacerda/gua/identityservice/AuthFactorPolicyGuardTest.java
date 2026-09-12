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

    private static String read(Path path) throws IOException {
        return Files.readString(path);
    }
}
