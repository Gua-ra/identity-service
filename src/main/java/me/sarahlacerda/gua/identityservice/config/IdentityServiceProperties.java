package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
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
    private final PlacementProperties placement = new PlacementProperties();
    private final AuthorityProperties authority = new AuthorityProperties();

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

        /**
         * This homeserver's roster entry id in the federation roster, which is what a placement record
         * carries (ADM-008 decision 7). It is a different namespace from {@link #id}: that one is this
         * deployment's local registry key and appears in {@code directory_entries.homeserver_id}, while
         * this one is federation state. The join between them is the Matrix domain, which is unique in
         * the roster. Left blank, {@code identity.placement.federation-id-aliases} is consulted and the
         * local id is used as-is if it has no alias.
         */
        private String federationId;

        /**
         * Base64 PKCS#8 Ed25519 private half of the roster membership key of this homeserver: the key
         * whose possession admission proved, and the only key a generation-1 placement record for this
         * homeserver may be signed with. Blank unless this deployment publishes records for it.
         */
        private String placementSigningPrivateKey;

        /** Where this homeserver's MAS placement evidence is read from, for the shadow comparison. */
        private final MasConfig mas = new MasConfig();
    }

    /**
     * Read-only coordinates of one homeserver's MAS, used by the shadow reconciler and nothing else.
     * Each MAS owns {@code upstream_oauth_links}, the only committed evidence of where an account
     * actually lives (ADM-008 decision 9).
     *
     * <p>Both paths are inert unless the matching switch under {@code identity.placement.mas} is on,
     * and neither exists on this deployment yet: the admin API needs the {@code urn:mas:admin} scope,
     * which MAS grants through {@code client_credentials} only to a client id listed in its policy data
     * {@code admin_clients}, and the SQL path needs a read-only role on each MAS database.
     */
    @Getter
    @Setter
    public static class MasConfig {

        /** The upstream OAuth provider id this identity-service is registered as in that MAS. */
        private String upstreamProviderId = "";

        private String adminApiBaseUrl = "";

        /** Token endpoint the {@code client_credentials} grant is requested from. */
        private String tokenUrl = "";

        private String clientId = "";

        private String clientSecret = "";

        /** JDBC URL of a read-only role on this MAS's database, for the fallback read path. */
        private String readOnlyJdbcUrl = "";

        private String readOnlyUsername = "";

        private String readOnlyPassword = "";
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

        /**
         * How many times an hour one account may submit a number that is not its own at a
         * reauthentication step, before further attempts are refused with {@code 429}.
         *
         * <p>
         * The account's own number is the secret being guessed here, and the caller already
         * holds a session, so nothing else bounds the guessing: a stolen session could
         * otherwise walk a country's numbering plan until one submission came back accepted.
         * Counted per user, not per address, because the address is the attacker's to change.
         */
        @Min(1)
        private int maxReauthPhoneAttemptsPerHour = 5;

        /**
         * How long an account must have gone without a completed sign-in before a delayed
         * account recovery may be requested. Unset falls back to {@link #pinResetCooldown}.
         */
        private Duration accountRecoveryDormancy;

        /**
         * How long a requested account recovery waits before it can be finished. Unset falls back
         * to {@link #pinResetCooldown}.
         */
        private Duration accountRecoveryWait;

        /**
         * Lets either recovery duration go below the 24 hour floor. Dev only, so a human can walk
         * a recovery through in minutes; startup refuses a shorter duration without it.
         */
        private boolean accountRecoveryAllowShortForTesting = false;

        public Duration getAccountRecoveryDormancy() {
            return accountRecoveryDormancy != null ? accountRecoveryDormancy : pinResetCooldown;
        }

        public Duration getAccountRecoveryWait() {
            return accountRecoveryWait != null ? accountRecoveryWait : pinResetCooldown;
        }

        /**
         * How long a recovery episode stays live from the moment it was requested: the wait, then
         * at least as long again to finish in, and never less than the dormancy period. Past it
         * the stamp is a leftover and is treated as absent, so an abandoned request can never
         * satisfy the wait of the next one.
         */
        public Duration getAccountRecoveryEpisodeLife() {
            Duration wait = getAccountRecoveryWait();
            Duration dormancy = getAccountRecoveryDormancy();
            return wait.plus(wait.compareTo(dormancy) >= 0 ? wait : dormancy);
        }
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
     * Generation-1 placement records and the shadow comparison (ADM-008 Phase 4, ADM-001 L6).
     *
     * <p>Every flag here defaults to off and the whole feature is inert until one is turned on: no
     * scheduler is started, no record is signed, no MAS is read and no new metric series appears. With
     * them all off this service behaves exactly as it did before the feature existed.
     *
     * <p>There is deliberately no flag that serves routing from a placement record. Phase 4 is
     * comparison only, and the resolution path never reads the placement table; that is an explicit
     * non-goal of the phase, not a switch someone forgot to add.
     */
    @Getter
    @Setter
    public static class PlacementProperties {

        /**
         * Base URL of the gua-resolver that holds the placement records. Deliberately named
         * {@code identity.placement.*}: the removed directory-publishing client lived under
         * {@code identity.resolver.*} and nothing may reintroduce that namespace (ADM-001 L1b).
         */
        private String resolverBaseUrl = "";

        /** Validity of a record this service issues. ADM-008 decision 7 fixes 400 days. */
        @NotNull
        private Duration recordValidity = Duration.ofDays(400);

        /** Age at which a still-valid record is re-issued, so it never approaches its expiry. */
        @NotNull
        private Duration reissueAfter = Duration.ofDays(300);

        /**
         * Maps a local registry homeserver id to a federation roster id, for comparison only. The legacy
         * synthesised homeserver has no roster identity and rows written before routing existed carry a
         * NULL or {@code default} homeserver id, so a comparison needs to be told what those meant. It
         * never affects which homeserver a record names: publishing uses the MAS link, never this.
         */
        @NotNull
        private Map<String, String> federationIdAliases = new LinkedHashMap<>();

        @NotNull
        private final PublishProperties publish = new PublishProperties();

        @NotNull
        private final ShadowProperties shadow = new ShadowProperties();

        @NotNull
        private final MasReadProperties mas = new MasReadProperties();
    }

    @Getter
    @Setter
    public static class PublishProperties {
        /**
         * Signs and publishes a generation-1 record for an account whose evidence says it has exactly
         * one home. Off by default; the shadow comparison is meant to run for days with this off before
         * anything is written to federation state.
         */
        private boolean enabled = false;
    }

    @Getter
    @Setter
    public static class ShadowProperties {

        /** Master switch for the reconciler. Off: no scheduler is started at all. */
        private boolean enabled = false;

        /** When the daily comparison runs. */
        @NotBlank
        private String cron = "0 20 3 * * *";

        /**
         * Writes the local routing choice back from the MAS link when the two disagree. Off by default:
         * a stale directory row is a data-quality finding, not a security event, and a comparison job
         * that also repairs is a comparison job nobody can read.
         */
        private boolean healDirectory = false;

        /**
         * Accounts whose local routing choice is known to differ from where they live, as MXID to the
         * expected roster homeserver id. The federation testbed deliberately placed an account away from
         * this deployment's default, and the exit criterion is "no stale rows except the listed ones",
         * which needs the list to be explicit rather than remembered.
         */
        @NotNull
        private Map<String, String> knownPlacements = new LinkedHashMap<>();

        @Min(1)
        private int batchSize = 500;
    }

    /**
     * Which MAS read path the reconciler uses. Both are off, and neither is available on this
     * deployment: see {@link MasConfig} for what granting each one requires.
     */
    @Getter
    @Setter
    public static class MasReadProperties {

        @NotNull
        private final MasSwitch adminApi = new MasSwitch();

        @NotNull
        private final MasSwitch sql = new MasSwitch();
    }

    @Getter
    @Setter
    public static class MasSwitch {
        private boolean enabled = false;
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

    /**
     * The account authority chain, adoption and the device lifecycle (ADM-009). Every flag defaults to
     * off or empty, so a deployment that sets none of them behaves exactly as it did before this feature
     * existed: every authority endpoint answers 503, no row is written to any authority table, and no
     * existing login, recovery, factor or genesis path changes.
     *
     * <p>Turning {@code enabled} on is refused at startup while no out-of-band notification channel is
     * wired, which is ADM-009 gate 2. Every window in that record is theatre without a channel that
     * survives both a SIM swap and the session revocation a recovery performs, because the account holder
     * is never told the window is running.
     */
    @Getter
    @Setter
    public static class AuthorityProperties {

        /**
         * Master switch. While it is false the whole feature is inert: the endpoints answer 503
         * {@code authority_disabled}, no challenge is minted and no chain row exists.
         */
        private boolean enabled = false;

        /**
         * Whether adoption may run outside dev.
         *
         * <p>Off by default, which ADM-009 gate 3 requires: production adoption stays refused until
         * ADM-002 Q6 answers the independence question, because under framework 0x01 the recovery
         * authority key shares the device store with the key it would veto. Dev may adopt behind this
         * flag and treats those accounts as disposable.
         */
        private boolean productionAdoption = false;

        /**
         * The opposition window of ADM-009 decision 4, which is also the quarantine of decision 5.
         *
         * <p>The window is the whole security of an adoption (ADM-001 O9), so startup refuses anything
         * under 24 hours without {@link #allowShortWindowsForTesting}. It runs on service time until
         * witnesses exist (ADM-002 R8).
         */
        @NotNull
        private Duration oppositionWindow = Duration.ofHours(72);

        /**
         * The wait an {@code AuthorityRecovery} signed by the committed recovery authority key runs,
         * which is ADM-002 D1's delta-r for framework 0x01 and deliberately not the adoption window.
         */
        @NotNull
        private Duration recoveryWindow = Duration.ofDays(7);

        /**
         * How long a minted challenge, and therefore the step-up that minted it, stays spendable. At or
         * under 15 minutes by ADM-009 decision 4 step 4; a larger value is clamped at startup.
         */
        @NotNull
        private Duration challengeTtl = Duration.ofMinutes(15);

        /** How long a browser-started approval stays signable (ADM-009 decision 6). */
        @NotNull
        private Duration approvalTtl = Duration.ofMinutes(10);

        /** How many approvals one account may hold at once (ADM-009 decision 6). */
        @Min(1)
        private int maxLiveApprovals = 3;

        /**
         * Lifts the 24-hour floor on the windows above, for a dev deployment where a human walks a
         * transition through. Nothing else may set it.
         */
        private boolean allowShortWindowsForTesting = false;

        /**
         * The registered OIDC client ids whose access tokens count as a native session.
         *
         * <p>ADM-009 decision 4 step 1: a session still inside the web view cannot start adoption, which
         * is the ADM-008:143 problem stated as a rule. The value is compared against the client the token
         * was accepted on, which comes from the verified audience, never from anything the caller sends
         * alongside it. The forwarded downstream-client marker is deliberately not used: it is
         * client-asserted, and the existing beta gate says so in as many words.
         *
         * <p>Empty by default, so with no configuration every native-only endpoint refuses. That is the
         * safe direction: a deployment that has not said which client is its app has not earned the right
         * to have one of them root an account.
         */
        @NotNull
        private List<String> nativeClientIds = new ArrayList<>();

        /**
         * How long a candidate device key stays grantable (ADM-009 decision 5, revision 4).
         *
         * <p>Short, because a candidate is a step in a ceremony two people are performing right now. One left
         * lying around is a key over which a grant could later be signed without anybody comparing anything.
         */
        @NotNull
        private Duration candidateLife = Duration.ofMinutes(10);

        /** The out-of-band channel of gate 2. Off by default, which is why gate 2 still blocks. */
        @Valid
        @NotNull
        private NotificationProperties notifications = new NotificationProperties();

        /** Publishing the settled chain head to the transparency log (ADM-009 decision 12). */
        @Valid
        @NotNull
        private final PublicationProperties publication = new PublicationProperties();
    }

    /**
     * Publishing the settled authority chain head as the {@code ACCOUNT_AUTHORITY} leaf ADM-009
     * decision 12 reserves.
     *
     * <p>A separate switch from {@code identity.authority.enabled}, deliberately, so the chain can run for
     * as long as it takes to validate it while nothing is written to federation state. With this off the
     * chain behaves exactly as it does today: no head object is signed, no resolver is contacted, and no
     * publication row exists. Decision 12 says the gap is a missing publication rather than a missing
     * signature, and this is the switch that closes it, one environment at a time.
     *
     * <p>Turning it on is refused at startup unless the homeserver it publishes under is named, this
     * deployment holds that homeserver's roster membership key, and the resolver is configured:
     * {@code AuthorityPublicationStartupCheck}. Rollback is turning it back off, with the table left in
     * place.
     */
    @Getter
    @Setter
    public static class PublicationProperties {

        /**
         * Master switch. Off by default; while it is false nothing is signed and nothing is sent.
         */
        private boolean enabled = false;

        /**
         * Base URL of the gua-resolver that holds the published heads.
         *
         * <p>Its own value rather than {@code identity.placement.resolver-base-url}, even though both
         * point at the same service, so the two features stay independently deployable and one rollback
         * cannot silently disable the other. Never {@code identity.resolver.*}: that namespace belonged to
         * the removed directory-publishing client (ADM-001 L1b).
         */
        private String resolverBaseUrl = "";

        /**
         * The federation roster id of the homeserver whose chains this deployment publishes.
         *
         * <p>Named explicitly rather than derived per account. The head is an assertion by the homeserver
         * that stores the chain, and the only homeserver this deployment can honestly assert for is one
         * whose membership key it holds; a value guessed from a local routing row would put a roster id
         * inside a signed object on the strength of state that row is allowed to be stale about. Empty by
         * default, and startup refuses publishing without it.
         */
        private String homeserverId = "";

        /**
         * Validity of a head object this service issues. Capped at the 400 days
         * {@code AuthorityHeadRecordCodec.MAX_VALIDITY} fixes.
         *
         * <p>It is what turns a homeserver that stops publishing into a visible stale state in the client
         * rather than into silence. It does not make withholding detectable, which needs the
         * non-membership proof ADM-005 owns.
         */
        @NotNull
        private Duration headValidity = Duration.ofDays(400);

        /**
         * Age at which a still-valid head is re-issued, so a long-quiet account's attestation never
         * reaches its expiry.
         *
         * <p>Checked on the same lazy path settlement runs on, never on a timer, so an account with no
         * transitions costs one extra leaf per interval and nothing in between. Shorter than
         * {@link #headValidity} or startup refuses it.
         */
        @NotNull
        private Duration republishAfter = Duration.ofDays(300);

        /**
         * How long an unacknowledged head waits before it is retried.
         *
         * <p>The catch-up rides the lazy path the account holder's own reads take, so a resolver that cannot
         * be reached would otherwise put a socket timeout in front of every one of those reads. This is the
         * only thing that bounds retries; there is no queue and no scheduler, and a head still unsent when
         * the next transition happens is sent then.
         */
        @NotNull
        private Duration retryAfter = Duration.ofMinutes(5);
    }

    /**
     * The security-notification channel ADM-009 gate 2 requires, and the two transports that carry it.
     *
     * <p>Off by default, and that is not a formality: with no transport configured
     * {@code AuthorityPushNotifier.isOutOfBand()} answers false, so a deployment that turns
     * {@code identity.authority.enabled} on without configuring one still fails to start. Turning the
     * feature on and turning a channel on are deliberately two decisions, because the credentials below are
     * two secrets this service has never held.
     */
    @Getter
    @Setter
    public static class NotificationProperties {

        /**
         * Master switch for the channel. While it is false no registration is accepted, nothing is sent,
         * and no credential is read, so a half-configured deployment holds no push secrets at all.
         */
        private boolean enabled = false;

        /**
         * How long a registration counts as a channel with nothing heard from it.
         *
         * <p>Far past any window, because the row's job is to survive a recovery and be there when a window
         * opens weeks later. It bounds retention rather than liveness.
         */
        @NotNull
        private Duration registrationLife = Duration.ofDays(180);

        /**
         * How many consecutive permanent transport failures retire a registration.
         *
         * <p>A destination the transport says is gone must stop counting as a channel, or gate 2 passes on
         * a promise nobody can keep.
         */
        @Min(1)
        private int failureLimit = 3;

        @Valid
        @NotNull
        private ApnsProperties apns = new ApnsProperties();

        @Valid
        @NotNull
        private FcmProperties fcm = new FcmProperties();
    }

    /**
     * Apple's own push service, spoken directly.
     *
     * <p>Directly rather than through the Matrix push gateway, because that gateway's only exposed path
     * takes a Matrix event notification keyed on a pushkey this service never sees, it is unauthenticated,
     * and it runs in one namespace only. Routing a security alert through it would mean forging a
     * notification and making the channel only as trustworthy as an endpoint that takes anyone's POST.
     */
    @Getter
    @Setter
    public static class ApnsProperties {

        /** Empty means this transport is not configured, which is the default. */
        private String baseUrl = "";

        /** The ES256 signing key id of the p8, which becomes the JWT's kid. */
        private String keyId = "";

        /** The Apple team id, which becomes the JWT's iss. */
        private String teamId = "";

        /** The PKCS#8 body of the p8, base64. Never logged, and absent by default. */
        private String privateKeyPkcs8Base64 = "";

        /**
         * Maps the app id the client already sends to the APNs topic.
         *
         * <p>One key addresses every topic of the team, so the map exists to pick the topic and not a
         * credential, and it is the same constant the Matrix pusher uses so the two cannot drift.
         */
        @NotNull
        private Map<String, String> topics = new LinkedHashMap<>();

        /** How long a minted provider token is reused before another is signed. Apple's cap is an hour. */
        @NotNull
        private Duration tokenLife = Duration.ofMinutes(50);
    }

    /**
     * Firebase Cloud Messaging v1, with the bearer minted here rather than by a Google library.
     *
     * <p>The nimbus library is already on this classpath for the OIDC work, so the service-account
     * assertion and its exchange cost no new dependency, no new transitive tree and no new credential
     * loading path. The token is cached to its own expiry.
     */
    @Getter
    @Setter
    public static class FcmProperties {

        /** Empty means this transport is not configured, which is the default. */
        private String baseUrl = "";

        /** The Firebase project the messages are sent into. */
        private String projectId = "";

        /** The service account's client_email, which is the assertion's iss and sub. */
        private String clientEmail = "";

        /** The PKCS#8 body of the service account's RSA key, base64. Never logged. */
        private String privateKeyPkcs8Base64 = "";

        /** Where the assertion is exchanged for a bearer. */
        private String tokenUri = "https://oauth2.googleapis.com/token";

        /** Refreshed this long before the bearer's own expiry, so a send never races the exchange. */
        @NotNull
        private Duration refreshSkew = Duration.ofMinutes(5);
    }
}
