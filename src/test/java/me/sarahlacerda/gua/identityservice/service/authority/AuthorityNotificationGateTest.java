// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * ADM-009 gate 2, and the two window rules beside it, as a startup refusal rather than as a sentence in a
 * document.
 *
 * <p>Every window in ADM-009 rests on the account holder hearing that it is running. With only the channels this
 * service has today, a SIM-swap attacker holds the phone and the recovery that preceded them emptied the
 * sessions, so the window is unwitnessed and the delay protects nobody. That is why the gate blocks production
 * rather than being an aspiration.
 */
class AuthorityNotificationGateTest {

    @Test
    void theFeatureOffStartsWhateverElseIsConfigured() {
        AuthorityProperties authority = new AuthorityProperties();
        authority.setOppositionWindow(Duration.ofMinutes(1));
        authority.setChallengeTtl(Duration.ofDays(1));

        // Inert. Nothing is read, so a half-configured deployment with the flag off behaves exactly as it did
        // before the feature existed.
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
    void theShippedNotifierIsNotSuchAChannelAndSaysSo() {
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

        // A transport being down must not roll back a transition that was already accepted, and it must not
        // stop the holder being told on the other channels.
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

        // A longer TTL would make the step-up older than the record it authorizes, which is the freshness
        // defect the whole preimage rule exists to close.
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

    /** Stands in for the channel gate 2 requires, so the other rules can be tested past it. */
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
