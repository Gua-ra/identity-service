package me.sarahlacerda.gua.identityservice.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MatrixLoginResponse(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("user_id") String userId,
    @JsonProperty("device_id") String deviceId
) { }
