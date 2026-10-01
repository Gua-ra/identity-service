package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import jakarta.validation.Valid;
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

    @NotNull
    private Duration authorizationCodeTtl = Duration.ofMinutes(5);

    @NotNull
    private Duration accessTokenTtl = Duration.ofMinutes(15);

    @NotNull
    private Duration idTokenTtl = Duration.ofMinutes(15);

    @Valid
    private final Signing signing = new Signing();

    @Valid
    private List<ClientRegistration> clients = new ArrayList<>();

    @Getter
    @Setter
    public static class Signing {
        @NotBlank
        private String keyId = "oidc-signing-key";

        /** If blank, an ephemeral key is generated on boot (dev only). */
        private String privateKey;

        private String publicKey;
    }

    @Getter
    @Setter
    public static class ClientRegistration {
        @NotBlank
        private String clientId;

        /** When blank the client is public and must use PKCE. */
        private String clientSecret;

        @NotNull
        private List<String> redirectUris = new ArrayList<>();

        @NotNull
        private List<String> allowedScopes = List.of("openid");

        private boolean requirePkce;
    }
}

