package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Status of the authenticated user's security PIN")
public record PinStatusResponse(
        @Schema(description = "True when the user has configured a security PIN") boolean hasPin) {
}
