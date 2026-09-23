// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;
import lombok.Setter;

/**
 * A new device offering its own public key for a grant (ADM-009 decision 5, revision 4).
 *
 * <p>The public half only. The new device generates its key and never receives another device's, so what
 * crosses between the two phones is these 32 bytes and the fingerprint the server computes from them.
 */
@Getter
@Setter
@Schema(description = "A device authority key offered for a grant")
public class AuthorityCandidateRequest {

    @NotBlank
    @Size(max = 64)
    @Schema(description = "Raw 32-byte Ed25519 device authority key, base64url",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String deviceKeyB64;

    @Size(max = 64)
    @Schema(description = "What this device suggests calling itself, at most the 16 bytes of UTF-8 a "
            + "record's label may carry")
    private String label;
}
