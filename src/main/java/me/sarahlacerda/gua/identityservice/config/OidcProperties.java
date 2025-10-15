package me.sarahlacerda.gua.identityservice.config;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "oidc")
public class OidcProperties {

    @NotBlank
    private String issuer;

    @NotBlank
    private String jwtSigningSecret;

    @NotNull
    private Duration authorizationCodeTtl = Duration.ofMinutes(5);

    @NotNull
    private Duration accessTokenTtl = Duration.ofMinutes(15);

    @NotNull
    private Duration idTokenTtl = Duration.ofMinutes(15);

    @NotBlank
    private String jwkKeyId = "oidc-signing-key";

    public byte[] signingKey() {
        return jwtSigningSecret.getBytes(StandardCharsets.UTF_8);
    }
}
