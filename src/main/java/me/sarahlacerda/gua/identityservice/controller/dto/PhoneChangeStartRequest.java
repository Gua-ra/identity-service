package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Step 1 of a phone-number change. The caller must already hold a
 * {@code PHONE_CHANGE}-scoped reauth token (from /account/reauth/start +
 * /account/reauth/verify) AND prove a non-phone factor: their account PIN when
 * one is set, and/or a passkey assertion. The reauth token alone is insufficient
 * because it only proves a current-phone OTP a SIM-swap attacker could control.
 */
@Getter
@Setter
@Schema(description = "Start a phone-number change: re-auth proof + step-up factor + the new number")
public class PhoneChangeStartRequest {

    @NotBlank
    @Schema(description = "Single-use, PHONE_CHANGE-scoped reauth token from /account/reauth/verify")
    private String reauthToken;

    @NotBlank
    @Schema(description = "The new phone number. Normalized to E.164 server-side (default region CA/+1).",
            example = "+14155550123")
    private String newPhone;

    @Schema(description = "Account PIN (required when the account has a PIN set; ignored otherwise).",
            example = "123456")
    private String pin;

    @Schema(description = "Passkey assertion session id from the in-app WebAuthn ceremony (optional step-up).")
    private String passkeyAuthSessionId;

    @Schema(description = "Passkey assertion response JSON from the in-app WebAuthn ceremony (optional step-up).")
    private com.fasterxml.jackson.databind.JsonNode passkeyCredential;
}
