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

    /**
     * Whether {@code POST /oauth2/account-deleted} acts on notices. Off, it answers 503 before reading any
     * credential. On only where every confidential client's secret is held by that client alone: the
     * secret is all a notice needs to delete an account on the client's homeservers.
     */
    private boolean accountDeletionNoticesEnabled = false;

    @Getter
    @Setter
    public static class Signing {
        /** Key identifier published in the JWKS document. */
        @NotBlank
        private String keyId = "oidc-signing-key";

        /** PEM-encoded RSA PKCS#8 private key. If blank, an ephemeral key is generated on boot (dev only). */
        private String privateKey;

        /** Optional PEM-encoded RSA public key (X.509 SubjectPublicKeyInfo). Derived from the private key when absent. */
        private String publicKey;
    }

    @Getter
    @Setter
    public static class ClientRegistration {
        @NotBlank
        private String clientId;

        /** Plain-text client secret. When blank the client is treated as public and MUST use PKCE. */
        private String clientSecret;

        @NotNull
        private List<String> redirectUris = new ArrayList<>();

        @NotNull
        private List<String> allowedScopes = List.of("openid");

        /** When true, PKCE is mandatory even if a secret is configured. Always true for public clients. */
        private boolean requirePkce;

        /**
         * Registry ids of the homeservers whose accounts this client may report deleted: the ids under
         * {@code identity.routing.homeservers}, or {@code default} for the legacy single homeserver.
         * Empty: none. A public client may report nothing, whatever this lists.
         */
        @NotNull
        private List<String> homeserverIds = new ArrayList<>();
    }
}

