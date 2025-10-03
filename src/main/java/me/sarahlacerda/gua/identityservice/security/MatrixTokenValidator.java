package me.sarahlacerda.gua.identityservice.security;

import java.io.IOException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class MatrixTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(MatrixTokenValidator.class);

    private final WebClient client;
    private final ObjectMapper objectMapper;

    public MatrixTokenValidator(WebClient.Builder webClientBuilder, IdentityServiceProperties properties) {
        this.client = webClientBuilder.clone()
            .baseUrl(properties.getMatrix().getClientApiBaseUrl())
            .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
    }

    public Optional<String> validate(String accessToken) {
        try {
            byte[] responseBytes = client.get()
                .uri("/_matrix/client/v3/account/whoami")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(byte[].class)
                .onErrorResume(ex -> {
                    log.warn("Matrix whoami validation failed: {}", ex.getMessage());
                    return Mono.empty();
                })
                .block();
            if (responseBytes == null || responseBytes.length == 0) {
                return Optional.empty();
            }
            WhoAmIResponse response = objectMapper.readValue(responseBytes, WhoAmIResponse.class);
            return Optional.ofNullable(response).map(WhoAmIResponse::userId);
        } catch (Exception ex) {
            if (ex instanceof IOException ioEx) {
                log.warn("Matrix whoami decoding failed: {}", ioEx.getMessage());
            } else {
                log.warn("Matrix whoami request failed: {}", ex.getMessage());
            }
            return Optional.empty();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record WhoAmIResponse(@com.fasterxml.jackson.annotation.JsonProperty("user_id") String userId) { }
}
