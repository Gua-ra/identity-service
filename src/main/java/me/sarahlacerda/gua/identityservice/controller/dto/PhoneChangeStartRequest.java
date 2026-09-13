package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Step 1 of a phone-number change. The caller must already hold a
 * {@code PHONE_CHANGE}-scoped reauth token (from /account/reauth/start +
 * /account/reauth/verify) AND prove a non-phone factor: a user-verifying passkey
 * assertion, or the account PIN when one is set. The reauth token alone is
 * insufficient because it only proves a current-phone OTP a SIM-swap attacker could
 * control.
 *
 * <p>
 * There is no field here for saying which factors the caller cannot use, and none may
 * be added. Anyone holding a session could set it, so it would be a way to ask for the
 * weaker factor rather than a description of the device.
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

    @Schema(description = "Account PIN. Required when the account has a PIN and no passkey assertion is "
            + "supplied; not consulted when a user-verifying assertion is accepted, since that is the "
            + "stronger factor. Ignored for an account with no PIN.", example = "123456")
    private String pin;

    @Schema(description = "Step-up ceremony id from POST /security/passkey/stepup/options. Supplied with "
            + "passkeyCredential, it settles the step-up on its own and the PIN is not asked for. A "
            + "sign-in assertion is not accepted here: the step-up ceremony demands user verification, "
            + "and the challenge is single use whether it is accepted or refused.")
    private String passkeyStepUpId;

    @Schema(description = "Passkey assertion response JSON from the step-up WebAuthn ceremony (optional step-up).")
    private com.fasterxml.jackson.databind.JsonNode passkeyCredential;
}
