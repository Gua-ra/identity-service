package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "A beta-access sign-up submitted from the public gua.global form")
public class BetaSignupRequest {

    @NotBlank
    @Email
    @Size(max = 254)
    @Schema(description = "Email to invite to the beta", example = "ana@example.com")
    private String email;

    @NotBlank
    @Pattern(regexp = "(?i)ios|android", message = "platform must be ios or android")
    @Schema(description = "Target platform", example = "ios", allowableValues = {"ios", "android"})
    private String platform;

    /**
     * Anti-spam honeypot. Hidden from real users via CSS; bots tend to fill every
     * field. Any non-empty value means the submission is silently dropped.
     */
    @Schema(hidden = true)
    private String website;
}
