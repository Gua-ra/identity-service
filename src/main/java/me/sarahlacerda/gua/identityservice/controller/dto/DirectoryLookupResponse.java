package me.sarahlacerda.gua.identityservice.controller.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@AllArgsConstructor
@Schema(description = "Contacts from the submitted phone numbers that are on Gua and discoverable")
public class DirectoryLookupResponse {

    @Schema(description = "Contacts that already have a Gua account")
    private List<ContactMatchView> matches;

    @Schema(description = "Single contact match entry")
    public record ContactMatchView(
        @Schema(description = "The submitted phone number that matched", example = "+5511999998888") String phone,
        @Schema(description = "Matrix user identifier for the contact", example = "@friend:gua.global") String userId,
        @Schema(description = "Global Gua username, when assigned", example = "friend") String username,
        @Schema(description = "Contact display name, if shared", example = "Friend") String displayName
    ) { }
}
