package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Acknowledgement that a public submission was accepted")
public record PublicSubmissionResponse(
        @Schema(description = "Always true when the request was accepted", example = "true")
        boolean accepted) {

    public static PublicSubmissionResponse ok() {
        return new PublicSubmissionResponse(true);
    }
}
