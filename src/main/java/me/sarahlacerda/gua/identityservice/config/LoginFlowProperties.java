package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "idp.login")
public class LoginFlowProperties {

    /** Must not collide with the /login/* API prefix. */
    @NotBlank
    private String uiUrl = "/signin";

    @NotNull
    private Duration sessionTtl = Duration.ofMinutes(10);

    @NotBlank
    private String cookieName = "gua_login";

    /** Disable only for plain-HTTP local development. */
    private boolean cookieSecure = true;

    @NotNull
    private Enroll enroll = new Enroll();

    @Getter
    @Setter
    public static class Enroll {
        @NotBlank
        private String redirectUri = "global.gua:/oidc";

        /** Allowed enrollment callback URIs. Values must match exactly. */
        private List<String> redirectUris = new ArrayList<>();

        @NotNull
        private Duration tokenTtl = Duration.ofMinutes(2);

        public List<String> allowedRedirectUris() {
            List<String> configured = redirectUris.stream()
                    .map(String::trim)
                    .filter(entry -> !entry.isEmpty())
                    .toList();
            return configured.isEmpty() ? List.of(redirectUri) : configured;
        }
    }

    @NotNull
    private Registration registration = new Registration();

    @Getter
    @Setter
    public static class Registration {
        private boolean webAllowlistEnabled = false;

        /** Numbers that already have an account need no entry. */
        private List<String> webAllowlist = new ArrayList<>();

        /** Client-asserted marker for native app flows. A convenience, not a security boundary. */
        @NotBlank
        private String nativeClientMarker = "native";
    }

    @NotNull
    private Passkeys passkeys = new Passkeys();

    @Getter
    @Setter
    public static class Passkeys {
        private boolean enabled = true;

        @NotBlank
        private String rpId = "localhost";

        @NotBlank
        private String rpName = "Gua";

        private List<String> origins = new ArrayList<>(List.of("http://localhost:5173", "http://localhost:8080"));

        @NotNull
        private Duration challengeTtl = Duration.ofMinutes(5);

        private long timeoutMillis = 60_000L;
    }
}
