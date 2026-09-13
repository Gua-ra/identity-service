package me.sarahlacerda.gua.identityservice.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class AccountRecoveryDurationValidatorTest {

    private static IdentityServiceProperties.SecurityProperties security() {
        return new IdentityServiceProperties().getSecurity();
    }

    @Test
    void unsetDurationsFallBackToThePinResetCooldown() {
        IdentityServiceProperties.SecurityProperties security = security();
        security.setPinResetCooldown(Duration.ofDays(5));

        assertThat(security.getAccountRecoveryDormancy()).isEqualTo(Duration.ofDays(5));
        assertThat(security.getAccountRecoveryWait()).isEqualTo(Duration.ofDays(5));
        assertThat(security.getAccountRecoveryEpisodeLife()).isEqualTo(Duration.ofDays(10));
    }

    @Test
    void setDurationsWinOverTheFallback() {
        IdentityServiceProperties.SecurityProperties security = security();
        security.setAccountRecoveryDormancy(Duration.ofDays(30));
        security.setAccountRecoveryWait(Duration.ofDays(2));

        assertThat(security.getAccountRecoveryDormancy()).isEqualTo(Duration.ofDays(30));
        assertThat(security.getAccountRecoveryWait()).isEqualTo(Duration.ofDays(2));
    }

    @Test
    void theDefaultsStart() {
        assertThatCode(() -> AccountRecoveryDurationValidator.validate(security())).doesNotThrowAnyException();
    }

    @Test
    void exactlyTheFloorStarts() {
        IdentityServiceProperties.SecurityProperties security = security();
        security.setAccountRecoveryDormancy(Duration.ofHours(24));
        security.setAccountRecoveryWait(Duration.ofHours(24));

        assertThatCode(() -> AccountRecoveryDurationValidator.validate(security)).doesNotThrowAnyException();
    }

    @Test
    void aDormancyOrAWaitBelowTheFloorRefusesToStart() {
        IdentityServiceProperties.SecurityProperties shortDormancy = security();
        shortDormancy.setAccountRecoveryDormancy(Duration.ofMinutes(2));
        assertThatThrownBy(() -> AccountRecoveryDurationValidator.validate(shortDormancy))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("allow-short-for-testing");

        IdentityServiceProperties.SecurityProperties shortWait = security();
        shortWait.setAccountRecoveryWait(Duration.ofHours(24).minusSeconds(1));
        assertThatThrownBy(() -> AccountRecoveryDurationValidator.validate(shortWait))
                .isInstanceOf(IllegalStateException.class);

        // The fallback is held to the same floor.
        IdentityServiceProperties.SecurityProperties shortFallback = security();
        shortFallback.setPinResetCooldown(Duration.ofHours(1));
        assertThatThrownBy(() -> AccountRecoveryDurationValidator.validate(shortFallback))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theTestingSwitchLiftsTheFloor() {
        IdentityServiceProperties.SecurityProperties security = security();
        security.setAccountRecoveryDormancy(Duration.ofMinutes(2));
        security.setAccountRecoveryWait(Duration.ofMinutes(3));
        security.setAccountRecoveryAllowShortForTesting(true);

        assertThatCode(() -> AccountRecoveryDurationValidator.validate(security)).doesNotThrowAnyException();
    }
}
