package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UsernameResolutionResponse(
        String username,
        @JsonProperty("user_id") String userId,
        String homeserver,
        @JsonProperty("display_name") String displayName) {
}
