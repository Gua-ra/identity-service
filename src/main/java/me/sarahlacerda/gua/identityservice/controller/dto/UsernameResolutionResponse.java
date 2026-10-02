package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of resolving a global Gua username to its account location.
 *
 * @param username     the resolved (canonical) username
 * @param userId       the Matrix user id (MXID) backing this username
 * @param homeserver   the Matrix server name the account lives on
 * @param displayName  the account's display name, if any
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UsernameResolutionResponse(
        String username,
        @JsonProperty("user_id") String userId,
        String homeserver,
        @JsonProperty("display_name") String displayName) {
}
