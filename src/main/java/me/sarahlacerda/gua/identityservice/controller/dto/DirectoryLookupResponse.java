package me.sarahlacerda.gua.identityservice.controller.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@AllArgsConstructor
@Schema(description = "Response containing the contacts that matched the submitted digests")
public class DirectoryLookupResponse {

    @Schema(description = "Contacts that already have a Gua account")
    private List<DirectoryMatchView> matches;

    @Schema(description = "Single contact match entry")
    public record DirectoryMatchView(
        @Schema(description = "Digest that produced the match", example = "1f3c...") String digest,
        @Schema(description = "Matrix user identifier for the contact", example = "@friend:gua.global") String userId,
        @Schema(description = "Contact display name, if shared", example = "Friend") String displayName
    ) { }
}
