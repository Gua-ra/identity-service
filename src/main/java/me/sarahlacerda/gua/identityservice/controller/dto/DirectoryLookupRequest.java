package me.sarahlacerda.gua.identityservice.controller.dto;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "Payload containing hashed phone digests to resolve")
public class DirectoryLookupRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier whose address book is being queried", example = "@user:gua.global")
    private String userId;

    @NotEmpty
    @Schema(description = "Collection of HMAC-SHA256 digests produced by the client", example = "[\"1f3c...\", \"ab42...\"]")
    private List<@NotBlank String> digests;
}
