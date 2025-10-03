package me.sarahlacerda.gua.identityservice.domain;

public record MatrixSession(String accessToken, String userId, String deviceId, String homeserverBaseUrl) { }
