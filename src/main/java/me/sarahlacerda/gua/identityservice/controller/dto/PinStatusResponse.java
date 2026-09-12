package me.sarahlacerda.gua.identityservice.controller.dto;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * What the account has registered, and what the server will accept from it.
 *
 * <p>
 * Everything here is server truth about registration. Nothing here is a statement about
 * what the calling device can do, and there is no field for the client to say what it
 * cannot do: a client claim that a factor is unavailable is free for an attacker to make,
 * so it could only ever be a request for something weaker.
 */
@Schema(description = "Status of the authenticated user's security PIN and the factors the account holds")
public record PinStatusResponse(
        @Schema(description = "True when the user has configured a security PIN") boolean hasPin,

        @Schema(description = "Seconds still to run on the fresh-2FA hold before the account PIN may be spent "
                + "as the step-up factor on a phone-number change. 0 means no hold. Separate from the "
                + "minimum gap between two successful phone changes, which is reported as 425 on the "
                + "change endpoint itself.", example = "0") long changePhoneCooldownRemainingSeconds,

        @Schema(description = "True when the account has at least one passkey REGISTERED and this deployment "
                + "has passkeys enabled. It says nothing about whether the current device can use that "
                + "credential, which only the client knows and which the server never accepts as an "
                + "input.", example = "true") boolean passkeyRegistered,

        @Schema(description = "The strongest factor the account holds, and therefore the one to offer first: "
                + "PASSKEY, PIN or PHONE_OTP.", example = "PASSKEY") String preferredFactor,

        @Schema(description = "The factors POST /account/phone/change/start accepts as its step-up, strongest "
                + "first. A client should ask for the first one it can actually produce and fall back "
                + "down the list; producing none of them is 403 step_up_required.",
                example = "[\"PASSKEY\",\"PIN\"]") List<String> phoneChangeStepUpFactors) {
}
