// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPushTransport.Outcome;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What makes the channel a channel, and what makes it honestly not one.
 *
 * <p>The gate-2 question is answered by {@code isOutOfBand()}, and answering it wrongly is the failure that
 * matters most here: a deployment that believes it has a channel runs every window in ADM-009 without telling
 * anybody. So the two ways it can be false are pinned, the APNs provider token's caching is pinned because
 * Apple refuses one older than an hour, and the two status codes that mean "this destination is gone" are
 * pinned because a token nobody retires keeps counting as a channel forever.
 */
class AuthorityPushChannelTest {

    private static final Instant T0 = Instant.parse("2026-09-23T10:00:00Z");

    private IdentityServiceProperties properties;
    private MutableClock clock;
    private AuthorityPolicy policy;
    private AuthorityNotificationRegistry registry;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        clock = new MutableClock(T0);
        policy = new AuthorityPolicy(properties,
                mock(me.sarahlacerda.gua.identityservice.service.security.UserSecurityService.class));
        registry = mock(AuthorityNotificationRegistry.class);
    }

    // --- Gate 2's own question -----------------------------------------------

    @Test
    void aDeploymentWithTheChannelSwitchedOffHasNoChannel() {
        // The default. identity.authority.notifications.enabled is a decision separate from the chain's own
        // switch, because turning it on means this service starts holding two push credentials.
        assertThat(properties.getAuthority().getNotifications().isEnabled()).isFalse();

        AuthorityPushNotifier notifier = new AuthorityPushNotifier(registry,
                List.of(new StubTransport(Platform.APNS, true)), policy, clock);

        assertThat(notifier.isOutOfBand()).isFalse();
        assertThat(notifier.reachesOutOfBand("@sarah:gua.global")).isFalse();
    }

    @Test
    void theChannelSwitchedOnWithNoConfiguredTransportIsStillNotAChannel() {
        properties.getAuthority().getNotifications().setEnabled(true);

        // A bean that could not send anything is not a channel however it is wired, so the startup gate keeps
        // refusing a deployment that turned the chain on without a credential.
        AuthorityPushNotifier notifier = new AuthorityPushNotifier(registry,
                List.of(new StubTransport(Platform.APNS, false)), policy, clock);

        assertThat(notifier.isOutOfBand()).isFalse();
    }

    @Test
    void anAccountWithNoLiveRegistrationIsNotReachedEvenWhereTheDeploymentIsConfigured() {
        properties.getAuthority().getNotifications().setEnabled(true);
        when(registry.live("@sarah:gua.global", T0)).thenReturn(List.of());

        AuthorityPushNotifier notifier = new AuthorityPushNotifier(registry,
                List.of(new StubTransport(Platform.APNS, true)), policy, clock);

        // The half a startup check cannot answer: gate 2 is a promise to one account holder.
        assertThat(notifier.isOutOfBand()).isTrue();
        assertThat(notifier.reachesOutOfBand("@sarah:gua.global")).isFalse();
    }

    @Test
    void apendingTransitionNamesTheLabelAndTheTimeAndNothingElse() {
        properties.getAuthority().getNotifications().setEnabled(true);
        StubTransport transport = new StubTransport(Platform.APNS, true);
        when(registry.live("@sarah:gua.global", T0)).thenReturn(List.of(registration()));

        new AuthorityPushNotifier(registry, List.of(transport), policy, clock)
                .notifyTransitionPending("@sarah:gua.global", "ADOPT_ROOT", "iPhone",
                        T0.plus(Duration.ofHours(72)));

        assertThat(transport.sent).hasSize(1);
        StubTransport.Sent sent = transport.sent.getFirst();
        assertThat(sent.body()).contains("iPhone").contains("26 Sep 10:00 UTC");
        // The three things a notification may carry, and no fourth: no account id, no phone number, no room.
        assertThat(sent.body()).doesNotContain("@sarah:gua.global").doesNotContain("gua.global");
    }

    @Test
    void aTransportThatSaysTheDestinationIsGoneRetiresTheRegistration() {
        properties.getAuthority().getNotifications().setEnabled(true);
        StubTransport transport = new StubTransport(Platform.APNS, true);
        transport.outcome = Outcome.UNREGISTERED;
        AuthorityNotificationRegistration row = registration();
        when(registry.live("@sarah:gua.global", T0)).thenReturn(List.of(row));

        new AuthorityPushNotifier(registry, List.of(transport), policy, clock)
                .notifyTransitionCompleted("@sarah:gua.global", "DEVICE_GRANT", "iPad");

        verify(registry).recordOutcome(row, Outcome.UNREGISTERED, T0);
    }

    @Test
    void aRegistrationWhoseTransportIsNotConfiguredIsLeftAlone() {
        properties.getAuthority().getNotifications().setEnabled(true);
        StubTransport apns = new StubTransport(Platform.APNS, true);
        AuthorityNotificationRegistration fcmRow = registration();
        fcmRow.setPlatform(Platform.FCM);
        when(registry.live("@sarah:gua.global", T0)).thenReturn(List.of(fcmRow));

        new AuthorityPushNotifier(registry, List.of(apns), policy, clock)
                .notifyChannelRemoved("@sarah:gua.global", "iPad");

        assertThat(apns.sent).isEmpty();
        verify(registry, never()).recordOutcome(any(), any(), any());
    }

    // --- APNs ----------------------------------------------------------------

    @Test
    void theApnsProviderTokenIsCachedAndResignedBeforeApplesHourIsUp() throws Exception {
        configureApns();
        AuthorityApnsTransport transport = new AuthorityApnsTransport(properties, mock(HttpClient.class), clock);

        String first = transport.providerToken();
        clock.advance(Duration.ofMinutes(49));
        assertThat(transport.providerToken()).isEqualTo(first);

        clock.advance(Duration.ofMinutes(2));
        String second = transport.providerToken();
        assertThat(second).isNotEqualTo(first);

        SignedJWT jwt = SignedJWT.parse(second);
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("PYW67BQDP7");
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("BSLR4D6L28");
    }

    @Test
    void apnsSaysTheDestinationIsGoneWithFourTenAndWithBadDeviceToken() throws Exception {
        configureApns();
        HttpClient http = mock(HttpClient.class);
        AuthorityApnsTransport transport = new AuthorityApnsTransport(properties, http, clock);

        givenResponse(http, 410, "");
        assertThat(transport.send("token", "global.gua", "t", "b")).isEqualTo(Outcome.UNREGISTERED);

        givenResponse(http, 400, "{\"reason\":\"BadDeviceToken\"}");
        assertThat(transport.send("token", "global.gua", "t", "b")).isEqualTo(Outcome.UNREGISTERED);

        // Anything else is transient. A 503 from Apple must not retire an install that is perfectly alive.
        givenResponse(http, 503, "");
        assertThat(transport.send("token", "global.gua", "t", "b")).isEqualTo(Outcome.RETRYABLE);

        givenResponse(http, 200, "");
        assertThat(transport.send("token", "global.gua", "t", "b")).isEqualTo(Outcome.DELIVERED);
    }

    @Test
    void anUnconfiguredApnsTransportSaysSo() {
        assertThat(new AuthorityApnsTransport(properties, mock(HttpClient.class), clock).isConfigured()).isFalse();
    }

    private void configureApns() throws Exception {
        IdentityServiceProperties.ApnsProperties apns = properties.getAuthority().getNotifications().getApns();
        apns.setBaseUrl("https://api.push.example.invalid");
        apns.setKeyId("PYW67BQDP7");
        apns.setTeamId("BSLR4D6L28");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        apns.setPrivateKeyPkcs8Base64(
                Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded()));
        apns.setTokenLife(Duration.ofMinutes(50));
    }

    private static AuthorityNotificationRegistration registration() {
        return AuthorityNotificationRegistration.registered("@sarah:gua.global", "install-phone", Platform.APNS,
                "global.gua", "apns-token", "fingerprint", "iPhone", null, T0);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static void givenResponse(HttpClient http, int status, String body) throws Exception {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        when(http.send(any(HttpRequest.class), any())).thenReturn(response);
    }

    /** Records what the notifier asked to be sent, which is the only thing worth asserting about a payload. */
    private static final class StubTransport implements AuthorityPushTransport {

        private final Platform platform;
        private final boolean configured;
        private final List<Sent> sent = new ArrayList<>();
        private Outcome outcome = Outcome.DELIVERED;

        private StubTransport(Platform platform, boolean configured) {
            this.platform = platform;
            this.configured = configured;
        }

        @Override
        public Platform platform() {
            return platform;
        }

        @Override
        public boolean isConfigured() {
            return configured;
        }

        @Override
        public Outcome send(String token, String appId, String title, String body) {
            sent.add(new Sent(token, appId, title, body));
            return outcome;
        }

        private record Sent(String token, String appId, String title, String body) {
        }
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
