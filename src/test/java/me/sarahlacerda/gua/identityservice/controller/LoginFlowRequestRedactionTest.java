package me.sarahlacerda.gua.identityservice.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.controller.dto.SignInVerifyPinRequest;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController.EnrollStepUpOtpRequest;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController.OtpRequest;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController.PinRequest;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController.PinSetupRequest;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController.RecoveryCompleteRequest;

/**
 * The sign-in requests that carry a code, a PIN or a PIN challenge token never print it, so
 * turning on request or argument logging cannot write one to a log.
 */
class LoginFlowRequestRedactionTest {

    private static final String CODE = "246802";
    private static final String PIN = "739164";
    private static final String PIN_CHALLENGE_TOKEN = "pinChallengeToken-7c1f0e9a2b4d6f8h0j2k4m6n8p";

    @Test
    void noRequestPrintsItsCodeOrPin() {
        Map<Object, String> secrets = Map.of(
                new OtpRequest(CODE), CODE,
                new PinRequest(PIN), PIN,
                new PinSetupRequest(PIN, false), PIN,
                new RecoveryCompleteRequest(PIN), PIN,
                new EnrollStepUpOtpRequest("+16042259911", CODE), CODE);

        secrets.forEach((request, secret) -> assertThat(request.toString())
                .doesNotContain(secret)
                .contains("<redacted>")
                .startsWith(request.getClass().getSimpleName() + "["));
    }

    @Test
    void theRestOfARequestStillPrints() {
        assertThat(new PinSetupRequest(PIN, true).toString()).isEqualTo("PinSetupRequest[pin=<redacted>, skip=true]");
        assertThat(new EnrollStepUpOtpRequest("+16042259911", CODE).toString())
                .isEqualTo("EnrollStepUpOtpRequest[phoneNumber=+16042259911, code=<redacted>]");
    }

    /** The REST second sign-in leg, POST /signin/verify-pin. */
    @Test
    void theRestPinLegPrintsNeitherThePinNorItsChallengeToken() {
        SignInVerifyPinRequest request = new SignInVerifyPinRequest();
        request.setPinChallengeToken(PIN_CHALLENGE_TOKEN);
        request.setPin(PIN);

        assertThat(request.toString()).doesNotContain(PIN).doesNotContain(PIN_CHALLENGE_TOKEN);
        assertThat(request.getPin()).isEqualTo(PIN);
        assertThat(request.getPinChallengeToken()).isEqualTo(PIN_CHALLENGE_TOKEN);
    }

    /** Redacting the printout leaves the values themselves, and record equality, as they were. */
    @Test
    void theValuesAreUnchanged() {
        assertThat(new OtpRequest(CODE).code()).isEqualTo(CODE);
        assertThat(new PinRequest(PIN).pin()).isEqualTo(PIN);
        assertThat(new PinRequest(PIN)).isEqualTo(new PinRequest(PIN));
    }
}
