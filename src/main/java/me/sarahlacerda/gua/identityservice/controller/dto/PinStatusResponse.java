package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Status of the authenticated user's security PIN")
public record PinStatusResponse(
        @Schema(description = "True when the user has configured a security PIN") boolean hasPin,
        @Schema(description = "Seconds remaining on the post-PIN-write cooldown before the PIN can step up a "
                + "change-phone request. 0 when no cooldown is active (or the user has no PIN).") long changePhoneCooldownRemainingSeconds) {
}
