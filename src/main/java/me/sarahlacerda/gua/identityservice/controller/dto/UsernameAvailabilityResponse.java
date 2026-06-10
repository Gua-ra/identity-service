package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Result of a real-time username availability check.")
public record UsernameAvailabilityResponse(
        @Schema(description = "True when the username passes validation and is not already taken.", example = "true") boolean available) {
}
