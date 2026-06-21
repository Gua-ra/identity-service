package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "A support request submitted from the public gua.global support form")
public class SupportRequest {

    @NotBlank
    @Size(max = 120)
    @Schema(description = "Name of the person asking for help", example = "Ana Souza")
    private String name;

    @NotBlank
    @Email
    @Size(max = 254)
    @Schema(description = "Reply-to email address", example = "ana@example.com")
    private String email;

    @NotBlank
    @Size(max = 5000)
    @Schema(description = "What the person needs help with", example = "I didn't receive my verification code.")
    private String message;

    /**
     * Anti-spam honeypot. Hidden from real users via CSS; bots tend to fill every
     * field. Any non-empty value means the submission is silently dropped.
     */
    @Schema(hidden = true)
    private String website;
}
