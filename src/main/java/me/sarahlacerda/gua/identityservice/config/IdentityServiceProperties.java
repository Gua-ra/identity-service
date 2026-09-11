package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import org.springframework.http.HttpMethod;

@ConfigurationProperties(prefix = "identity")
@Validated
@Getter
public class IdentityServiceProperties {

    private final OtpProperties otp = new OtpProperties();
    private final MatrixProperties matrix = new MatrixProperties();
    private final RoutingProperties routing = new RoutingProperties();
    private final DirectoryProperties directory = new DirectoryProperties();
    private final SecurityProperties security = new SecurityProperties();
    private final SmsProperties sms = new SmsProperties();
    private final RateLimitProperties rateLimits = new RateLimitProperties();
    private final GenesisProperties genesis = new GenesisProperties();

    @Getter
    @Setter
    public static class OtpProperties {
        @Min(4)
        private int codeLength = 6;

        @NotNull
        private Duration ttl = Duration.ofMinutes(5);

        @Min(1)
        private int maxRequestsPerPhonePerHour = 5;

        @Min(1)
        private int maxRequestsPerIpPerHour = 10;

        /**
         * Wrong guesses one code may absorb before it is deleted. Counted per phone
         * in Redis next to the code and expiring with it; a new send resets it. The
         * endpoint limiters bound guesses per address, this bounds them per code.
         */
        @Min(1)
        private int maxVerifyAttempts = 5;

        @NotBlank
        private String smsTemplate = "Your Gua verification code is %s. Never share this code with anyone. Gua will never ask you for it.";

        @NotNull
        private Map<String, String> localizedSmsTemplates = new HashMap<>();
    }

    @Getter
    @Setter
    public static class MatrixProperties {
        @NotBlank
        private String adminApiBaseUrl;

        @NotBlank
        private String clientApiBaseUrl;

        @NotBlank
        private String homeserverDomain;

        @NotBlank
        private String adminAccessToken;
    }

    @Getter
    @Setter
    public static class DirectoryProperties {
        @NotBlank
        private String pepper;

        /**
         * Optional pin against silent pepper rotation/drift. The pepper is an
         * immutable, backed-up secret: changing it re-keys every phone digest and
         * orphans every existing directory row (forcing returning users into signup
         * and minting duplicate accounts). When set to the expected, non-reversible
         * fingerprint of the live pepper (see
         * {@code DirectoryPepperPinValidator}), the service FAILS FAST on startup if
         * the configured pepper does not match, so an accidental rotation is caught
         * loudly instead of silently corrupting identities. Leave blank in dev; pin
         * it in every long-lived environment. This is a fingerprint, never the pepper
         * itself, so it is safe to commit/store.
         */
        private String pepperFingerprint;

        /** Max phone numbers accepted per /directory/lookup request. */
        private int maxLookupBatch = 1000;
    }

    /**
     * Per-deployment routing / homeserver-registry configuration: the homeservers
     * this deployment provisions accounts to and the local rule for choosing one.
     * This is local configuration, not the federation roster, and the choice it
     * drives is not the committed placement of ADM-001 L6. When
     * {@code homeservers} is empty, the registry synthesises a single homeserver
     * from the legacy {@code identity.matrix.*} properties, so existing
     * single-homeserver deployments keep working with no config change.
     */
    @Getter
    @Setter
    public static class RoutingProperties {
        /** Placement strategy for new accounts: "single", "weighted", or "region". */
        @NotBlank
        private String strategy = "single";

        /** Homeserver id new accounts default to when a rule does not match. */
        private String defaultHomeserverId;

        @Valid
        private List<HomeserverConfig> homeservers = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class HomeserverConfig {
        @NotBlank
        private String id;

        @NotBlank
        private String domain;

        @NotBlank
        private String adminApiBaseUrl;

        @NotBlank
        private String clientApiBaseUrl;

        @NotBlank
        private String adminAccessToken;

        /** Optional placement hint, e.g. "br", "eu". */
        private String region;

        @Min(0)
        private int weight = 1;

        private boolean enabled = true;
    }

    @Getter
    @Setter
    public static class SecurityProperties {
        @NotNull
        private Duration pinResetCooldown = Duration.ofDays(7);

        @Min(1)
        private int maxPinAttempts = 5;

        @NotNull
        private Duration pinLockDuration = Duration.ofMinutes(15);

        @NotNull
        private Duration pinChangeCooldown = Duration.ofHours(24);

        @NotNull
        private Duration pinChangeChallengeTtl = Duration.ofMinutes(5);

        /**
         * Minimum time between successful phone-number changes for one account. A
         * fresh session + reauth proof should not let an attacker rapidly re-point the
         * account; the cooldown bounds how often the linked number can churn.
         */
        @NotNull
        private Duration phoneChangeCooldown = Duration.ofHours(24);

        /**
         * Lifetime of a phone-change challenge (Redis-only). The new-number OTP itself
         * has the shorter {@code identity.otp.ttl}; this is the window in which the
         * caller must submit it at {@code /account/phone/change/complete}.
         */
        @NotNull
        private Duration phoneChangeChallengeTtl = Duration.ofMinutes(10);

        /**
         * Per-challenge wrong-OTP cap for the new-number verification. Once reached,
         * both the OTP key and the challenge are destroyed (IP-independent), closing
         * the per-IP endpoint-limiter rotation bypass.
         */
        @Min(1)
        private int maxPhoneChangeOtpAttempts = 5;
    }

    @Getter
    public static class SmsProperties {
        private final TwilioProperties twilio = new TwilioProperties();

        @Getter
        @Setter
        public static class TwilioProperties {
            private boolean enabled = false;
            private String accountSid;
            private String authToken;
            /** Sender phone number (E.164). Used when {@code messagingServiceSid} is not set. */
            private String fromNumber;
            /** Twilio Messaging Service SID (preferred for production: number pool, opt-out/compliance).
             * Takes precedence over {@code fromNumber} when set. */
            private String messagingServiceSid;
        }
    }

    @Getter
    @Setter
    public static class RateLimitProperties {
        private boolean enabled = true;

        @Valid
        private final RateLimitConfig defaultConfig = new RateLimitConfig();

        @Valid
        private final List<RateLimitRule> endpoints = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class RateLimitConfig {
        @Min(1)
        private int limitForPeriod = 60;

        @NotNull
        private Duration refreshPeriod = Duration.ofMinutes(1);

        @NotNull
        private Duration timeoutDuration = Duration.ZERO;
    }

    @Getter
    @Setter
    public static class RateLimitRule extends RateLimitConfig {
        @NotBlank
        private String path;

        @Valid
        private Set<HttpMethod> methods = new HashSet<>();
    }

    /**
     * Account genesis and the accountId (ADM-008 Phase 3). Every flag defaults to off, so a deployment
     * that sets none of them behaves exactly as it did before this feature existed: the registration
     * endpoint answers 503, the {@code gua:} login-hint grammar is not parsed, and no account gets a
     * genesis row.
     *
     * <p>Nothing here is read for routing or for login in this phase.
     */
    @Getter
    @Setter
    public static class GenesisProperties {

        /**
         * Master switch. While it is false the whole feature is inert. When true, clients may register
         * an {@code AccountGenesis}, a {@code gua:} login hint is parsed, an attach is attempted for a
         * session that carries a handle, and an account created without one is given a bootstrap
         * accountId.
         */
        private boolean enabled = false;

        /**
         * Whether ids may be issued under recovery framework 0x01 for production use.
         *
         * <p>Off by default, which ADM-008 decision 4 requires outside dev, and
         * {@code POST /account/genesis} refuses {@code recoveryFrameworkId = 0x01} while it is off.
         * Framework 0x01 commits one recovery key and no delay bounds, so it waits on ADM-002 D1 fixing
         * the 0x01 bounds on both delays, and on the independence question ADM-002 Q6 decides: under
         * 0x01 the recovery key shares the device store with the key it would veto. Dev turns this on
         * and treats the ids it mints as disposable; there is no migration path from a 0x01 id to a
         * 0x02 one.
         */
        private boolean productionIssuance = false;

        /**
         * How long a registered but unattached genesis stays attachable. The attach challenge expires
         * with its login session, at or under this window.
         */
        @NotNull
        private Duration pendingTtl = Duration.ofMinutes(30);

        /**
         * Requires a native signup to present an attach handle. Kept off until the clients ship genesis
         * and are observed presenting handles; flipping it on refuses a native signup that presents
         * none, instead of giving it a bootstrap id.
         */
        private boolean requireForNative = false;

        @NotNull
        private BootstrapBackfillProperties bootstrapBackfill = new BootstrapBackfillProperties();

        @Getter
        @Setter
        public static class BootstrapBackfillProperties {
            /**
             * Mints a bootstrap accountId for every existing account that has none. Idempotent and
             * resumable, so it is safe to leave on and safe to rerun.
             */
            private boolean enabled = false;

            /** Accounts scanned per batch. */
            @Min(1)
            private int batchSize = 500;
        }
    }
}
