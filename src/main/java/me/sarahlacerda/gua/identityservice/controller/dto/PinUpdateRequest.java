package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Request payload for setting or updating a security PIN")
public class PinUpdateRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "New PIN to be stored", example = "987654")
    private String newPin;

    @Schema(description = "Current PIN, required when updating an existing PIN", example = "123456")
    private String currentPin;
}
