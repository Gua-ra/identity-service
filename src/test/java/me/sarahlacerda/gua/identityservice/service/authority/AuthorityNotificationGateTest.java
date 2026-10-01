// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class AuthorityNotificationGateTest {

    @Test
    void theFeatureOffStartsWhateverElseIsConfigured() {
        AuthorityProperties authority = new AuthorityProperties();
        authority.setOppositionWindow(Duration.ofMinutes(1));
        authority.setChallengeTtl(Duration.ofDays(1));

        AuthorityNotificationGate.validate(authority, false);
    }

    @Test
    void theFeatureOnWithNoOutOfBandChannelRefusesToStart() {
        AuthorityProperties authority = new AuthorityProperties();
        authority.setEnabled(true);

        assertThatThrownBy(() -> AuthorityNotificationGate.validate(authority, false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gate 2")
                .hasMessageContaining("a log line is not a channel");
    }

    @Test
    void aTransportWhoseKeyDoesNotLoadRefusesToStart() throws Exception {
        AuthorityProperties authority = enabledWithApnsKey("bm90LWEta2V5");

        assertThatThrownBy(() -> AuthorityNotificationGate.validate(authority, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("apns.private-key-pkcs8-base64")
                .hasMessageContaining("cannot sign announces nothing");
    }

    @Test
    void aStartThatLoadsAKeySaysSo() throws Exception {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(AuthorityNotificationGate.class);
        java.util.List<String> lines = new java.util.ArrayList<>();
        ch.qos.logback.core.AppenderBase<ch.qos.logback.classic.spi.ILoggingEvent> capture =
                new ch.qos.logback.core.AppenderBase<>() {
                    @Override
                    protected void append(ch.qos.logback.classic.spi.ILoggingEvent event) {
                        lines.add(event.getFormattedMessage());
                    }
                };
        capture.start();
        logger.addAppender(capture);
        try {
            java.security.KeyPair pair = java.security.KeyPairGenerator.getInstance("EC").generateKeyPair();
            String der = java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            AuthorityNotificationGate.validate(enabledWithApnsKey(der), true);
        } finally {
            logger.detachAppender(capture);
        }

        assertThat(lines).anySatisfy(line -> assertThat(line)
                .contains("apns.private-key-pkcs8-base64")
                .contains("loaded as a EC key"));
    }

    @Test
    void aTransportWhoseKeyIsThePemFileStarts() throws Exception {
        java.security.KeyPair pair = java.security.KeyPairGenerator.getInstance("EC").generateKeyPair();
        StringBuilder pem = new StringBuilder("-----BEGIN PRIVATE KEY-----\n")
                .append(java.util.Base64.getMimeEncoder().encodeToString(pair.getPrivate().getEncoded()))
                .append("\n-----END PRIVATE KEY-----\n");
        String configured = java.util.Base64.getEncoder()
                .encodeToString(pem.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        AuthorityNotificationGate.validate(enabledWithApnsKey(configured), true);
    }

    private static AuthorityProperties enabledWithApnsKey(String configured) {
        AuthorityProperties authority = new AuthorityProperties();
        authority.setEnabled(true);
        authority.getNotifications().getApns().setBaseUrl("https://api.push.apple.com");
        authority.getNotifications().getApns().setPrivateKeyPkcs8Base64(configured);
        return authority;
    }

    @Test
    void theLoggedNotifierIsNotAnOutOfBandChannel() {
        assertThat(new LoggedAuthorityNotifier().isOutOfBand()).isFalse();
    }

    @Test
    void oneWiredChannelIsWhatTheGateAsksAboutRatherThanAnyOneImplementation() {
        AuthorityNotifications withOnlyTheLog =
                new AuthorityNotifications(java.util.List.of(new LoggedAuthorityNotifier()));
        AuthorityNotifications withAChannel = new AuthorityNotifications(
                java.util.List.of(new LoggedAuthorityNotifier(), new OutOfBandForTest()));

        assertThat(withOnlyTheLog.hasOutOfBandChannel()).isFalse();
        assertThat(withAChannel.hasOutOfBandChannel()).isTrue();
    }

    @Test
    void aChannelThatThrowsDoesNotTakeTheTransitionWithIt() {
        AuthorityNotifications notifications =
                new AuthorityNotifications(java.util.List.of(new ThrowingForTest(), new OutOfBandForTest()));

        notifications.pending("@a:gua", "ADOPT_ROOT", "iPhone", java.time.Instant.now());
        notifications.cancelled("@a:gua", "ADOPT_ROOT", "iPhone");
        notifications.completed("@a:gua", "ADOPT_ROOT", "iPhone");
    }

    @Test
    void aWindowUnderTheFloorRefusesToStartWithoutTheTestingSwitch() {
        AuthorityProperties authority = enabledWithAChannel();
        authority.setOppositionWindow(Duration.ofHours(23));

        assertThatThrownBy(() -> AuthorityNotificationGate.validate(authority, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("O9");
    }

    @Test
    void theRecoveryWindowIsHeldToTheSameFloor() {
        AuthorityProperties authority = enabledWithAChannel();
        authority.setRecoveryWindow(Duration.ofHours(1));

        assertThatThrownBy(() -> AuthorityNotificationGate.validate(authority, true))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void exactlyTheFloorStarts() {
        AuthorityProperties authority = enabledWithAChannel();
        authority.setOppositionWindow(AuthorityNotificationGate.WINDOW_FLOOR);
        authority.setRecoveryWindow(AuthorityNotificationGate.WINDOW_FLOOR);

        AuthorityNotificationGate.validate(authority, true);
    }

    @Test
    void theTestingSwitchLiftsTheFloor() {
        AuthorityProperties authority = enabledWithAChannel();
        authority.setOppositionWindow(Duration.ofMinutes(2));
        authority.setRecoveryWindow(Duration.ofMinutes(2));
        authority.setAllowShortWindowsForTesting(true);

        AuthorityNotificationGate.validate(authority, true);
    }

    @Test
    void aChallengeThatWouldOutliveItsStepUpRefusesToStart() {
        AuthorityProperties authority = enabledWithAChannel();
        authority.setChallengeTtl(Duration.ofHours(1));

        assertThatThrownBy(() -> AuthorityNotificationGate.validate(authority, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("challenge-ttl");
    }

    @Test
    void theDefaultsStartOnceAChannelIsWired() {
        AuthorityNotificationGate.validate(enabledWithAChannel(), true);
    }

    private static AuthorityProperties enabledWithAChannel() {
        AuthorityProperties authority = new AuthorityProperties();
        authority.setEnabled(true);
        return authority;
    }

    private static final class OutOfBandForTest implements AuthorityNotifier {

        @Override
        public boolean isOutOfBand() {
            return true;
        }

        @Override
        public void notifyTransitionPending(String userId, String transition, String deviceLabel,
                java.time.Instant effectiveAt) {
        }

        @Override
        public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
        }

        @Override
        public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
        }
    }

    private static final class ThrowingForTest implements AuthorityNotifier {

        @Override
        public boolean isOutOfBand() {
            return false;
        }

        @Override
        public void notifyTransitionPending(String userId, String transition, String deviceLabel,
                java.time.Instant effectiveAt) {
            throw new IllegalStateException("the transport is down");
        }

        @Override
        public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
            throw new IllegalStateException("the transport is down");
        }

        @Override
        public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
            throw new IllegalStateException("the transport is down");
        }
    }
}
