package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to start a PIN change. Authorizes it with a passkey step-up assertion or the current PIN, then sends an OTP to the verified phone.")
public class PinChangeStartRequest {

    @NotBlank
    @Schema(description = "Verified phone number that will receive the OTP", example = "+5511987654321")
    private String phone;

    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "Current PIN. Required when no passkey assertion is supplied; not consulted when a "
            + "user-verifying assertion is accepted, since that is the stronger factor.", example = "123456")
    private String currentPin;

    @Schema(description = "Step-up ceremony id from POST /security/passkey/stepup/options. Supplied with "
            + "passkeyCredential, it authorizes the change on its own and the current PIN is not asked for.")
    private String passkeyStepUpId;

    @Schema(description = "Passkey assertion response JSON from the step-up WebAuthn ceremony (optional).")
    private com.fasterxml.jackson.databind.JsonNode passkeyCredential;
}
