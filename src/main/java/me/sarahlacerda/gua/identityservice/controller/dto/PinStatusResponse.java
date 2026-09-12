package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Status of the authenticated user's security PIN")
public record PinStatusResponse(
        @Schema(description = "True when the user has configured a security PIN") boolean hasPin,

        @Schema(description = "Seconds still to run on the fresh-2FA hold before the account PIN may be spent "
                + "as the step-up factor on a phone-number change. 0 means no hold. Separate from the "
                + "minimum gap between two successful phone changes, which is reported as 425 on the "
                + "change endpoint itself.", example = "0") long changePhoneCooldownRemainingSeconds) {
}
