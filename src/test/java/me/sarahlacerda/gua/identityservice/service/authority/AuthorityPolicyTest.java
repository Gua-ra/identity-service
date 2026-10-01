// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.ChainContext;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.Opposition;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.SlotOutcome;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorityPolicyTest {

    @Mock
    private UserSecurityService userSecurityService;

    private IdentityServiceProperties properties;
    private AuthorityPolicy policy;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        policy = new AuthorityPolicy(properties, userSecurityService);
    }

    @Test
    void everyEndpointIsUnavailableWhileTheFeatureIsOff() {
        properties.getAuthority().setEnabled(false);

        assertThat(policy.isEnabled()).isFalse();
        assertThat(codeOf(() -> policy.requireEnabled())).isEqualTo("authority_disabled");
    }

    @Test
    void adoptionIsRefusedUntilTheDeploymentSaysItMay() {
        assertThat(codeOf(() -> policy.requireAdoptionPermitted()))
                .isEqualTo("authority_adoption_not_permitted");

        properties.getAuthority().setAdoptionPermitted(true);

        assertThat(policy.isEnabled()).isTrue();
    }

    @Test
    void aRegisteredClientOfOursThatIsNotListedIsRefused() {
        assertThat(codeOf(() -> policy.requireNativeSession(Optional.of("gua-ios"))))
                .isEqualTo("authority_native_session_required");
        assertThat(policy.mayHoldAuthority(Optional.of("gua-ios"))).isFalse();

        properties.getAuthority().getNativeClientIds().add("gua-ios");

        policy.requireNativeSession(Optional.of("gua-ios"));
        assertThat(policy.mayHoldAuthority(Optional.of("gua-ios"))).isTrue();
        assertThat(codeOf(() -> policy.requireNativeSession(Optional.of("gua-web"))))
                .isEqualTo("authority_native_session_required");
    }

    @Test
    void aTokenThatNamesNoClientOfOursIsNotRefused() {
        // Homeserver-issued tokens, which both apps use, name no client of ours.
        policy.requireNativeSession(Optional.empty());

        assertThat(policy.mayHoldAuthority(Optional.empty())).isTrue();

        properties.getAuthority().getNativeClientIds().add("gua-ios");
        policy.requireNativeSession(Optional.empty());
    }

    @Test
    void noAcceptedSetContainsThePhoneCodeAtAnyStep() {
        for (Purpose purpose : Purpose.values()) {
            assertThat(policy.stepUpFor(purpose).accepted()).doesNotContain(AuthFactor.PHONE_OTP);
        }
        assertThat(policy.oppositionStepUp().accepted()).doesNotContain(AuthFactor.PHONE_OTP);
    }

    @Test
    void everyTransitionTakesThePasskeyAheadOfThePinAndNothingElse() {
        for (Purpose purpose : new Purpose[] { Purpose.ADOPT, Purpose.GRANT, Purpose.REVOKE, Purpose.RECOVER }) {
            assertThat(policy.stepUpFor(purpose).accepted())
                    .containsExactly(AuthFactor.PASSKEY, AuthFactor.PIN);
            assertThat(policy.stepUpFor(purpose).hardBlockWhenUnsatisfied()).isTrue();
        }
    }

    @Test
    void theBrowserStartedApprovalAsksForNoFactorBecauseADeviceSignatureIsTheProof() {
        assertThat(policy.stepUpFor(Purpose.APPROVE).required()).isFalse();
    }

    @Test
    void theFirstOppositionIsFreeAndEveryLaterOneNeedsAStepUp() {
        assertThat(policy.oppositionNeedsStepUp(0)).isFalse();
        assertThat(policy.oppositionNeedsStepUp(1)).isTrue();
        assertThat(policy.oppositionNeedsStepUp(7)).isTrue();
    }

    @Test
    void aFactorMintedInsideTheHoldCannotStartATransition() {
        Instant justNow = Instant.now();
        when(userSecurityService.freshFactorHoldRemaining(justNow)).thenReturn(600L);

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> policy.enforceFreshFactorHold(justNow), AuthorityTransitionException.class);

        assertThat(refusal.getCode()).isEqualTo("authority_factor_too_fresh");
        assertThat(refusal.getRetryAfterSeconds()).isEqualTo(600L);
    }

    @Test
    void anEstablishedFactorStartsATransitionAtOnce() {
        Instant old = Instant.now().minus(Duration.ofDays(30));
        when(userSecurityService.freshFactorHoldRemaining(old)).thenReturn(0L);

        policy.enforceFreshFactorHold(old);
    }

    @Test
    void anAccountRecoveredInsideTheHoldCannotStartATransition() {
        when(userSecurityService.recoveryCompletionHoldRemaining("@a:gua")).thenReturn(4321L);

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> policy.enforceRecoveryOutsideHold("@a:gua"), AuthorityTransitionException.class);

        assertThat(refusal.getCode()).isEqualTo("authority_recovery_too_recent");
        assertThat(refusal.getRetryAfterSeconds()).isEqualTo(4321L);
    }

    @Test
    void theChallengeAndTheStepUpShareOneAge() {
        assertThat(policy.challengeTtl()).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void adoptionIsOnlyEverTheFirstRecordOfABootstrapAccount() {
        policy.requirePermittedAt(AuthorityRecordType.ADOPT_ROOT, null, bootstrapEmpty());

        assertThat(codeOf(() -> policy.requirePermittedAt(AuthorityRecordType.ADOPT_ROOT, null,
                new ChainContext(false, false, true, 1)))).isEqualTo("authority_position_refused");
        assertThat(codeOf(() -> policy.requirePermittedAt(AuthorityRecordType.ADOPT_ROOT, null,
                new ChainContext(true, true, true, 1)))).isEqualTo("authority_position_refused");
    }

    @Test
    void recoveryIsNeverABootstrapAccountsFirstRecord() {
        assertThat(codeOf(() -> policy.requirePermittedAt(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, bootstrapEmpty())))
                .isEqualTo("authority_position_refused");
    }

    @Test
    void theAccountRecoveryPathIsRefusedOutrightOnAGenesisRootedAccount() {
        assertThat(codeOf(() -> policy.requirePermittedAt(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, new ChainContext(true, true, true, 1))))
                .isEqualTo("authority_position_refused");

        policy.requirePermittedAt(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, new ChainContext(true, true, true, 1));
    }

    @Test
    void theAccountRecoveryPathIsOpenToAnAdoptedBootstrapAccount() {
        policy.requirePermittedAt(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, new ChainContext(false, false, true, 1));
    }

    @Test
    void neitherRecoveryPathIsGatedOnTheAccountHavingNoActiveDevice() {
        policy.requirePermittedAt(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, new ChainContext(false, false, true, 3));
    }

    @Test
    void aGrantOrARevocationNeedsAnUnquarantinedActiveDeviceToExist() {
        for (AuthorityRecordType type : new AuthorityRecordType[] { AuthorityRecordType.DEVICE_GRANT,
                AuthorityRecordType.DEVICE_REVOKE }) {
            policy.requirePermittedAt(type, null, new ChainContext(false, false, true, 1));
            assertThat(codeOf(() -> policy.requirePermittedAt(type, null,
                    new ChainContext(false, false, true, 0)))).isEqualTo("authority_position_refused");
        }
    }

    @Test
    void aGrantedDeviceIsQuarantinedForOneWindow() {
        Instant now = Instant.now();

        assertThat(policy.quarantineUntil(now)).isEqualTo(now.plus(Duration.ofHours(72)));
    }

    @Test
    void aQuarantinedDeviceMayNotAuthorizeAnything() {
        assertThat(codeOf(() -> policy.requireNotQuarantined(true))).isEqualTo("authority_device_quarantined");
        policy.requireNotQuarantined(false);
    }

    @Test
    void aRevocationMayNotLeaveTheAccountWithNoUnquarantinedDevice() {
        policy.requireLeavesAnActiveDevice(1);
        assertThat(codeOf(() -> policy.requireLeavesAnActiveDevice(0))).isEqualTo("authority_last_device");
    }

    @Test
    void theDeviceAGrantNamesMayNotObjectToItsOwnGrant() {
        assertThat(policy.opposition(AuthorityRecordType.DEVICE_GRANT, null, true, false))
                .isEqualTo(Opposition.REFUSED);
        assertThat(policy.opposition(AuthorityRecordType.DEVICE_GRANT, null, false, false))
                .isEqualTo(Opposition.CANCELS);
    }

    @Test
    void theDeviceARevocationNamesMayNotVetoItsOwnRemoval() {
        assertThat(policy.opposition(AuthorityRecordType.DEVICE_REVOKE, null, true, false))
                .isEqualTo(Opposition.REFUSED);
        assertThat(policy.opposition(AuthorityRecordType.DEVICE_REVOKE, null, false, false))
                .isEqualTo(Opposition.CANCELS);
    }

    @Test
    void aNamedDeviceMayObjectWhenAcceptingWouldLeaveTheSignerAlone() {
        assertThat(policy.opposition(AuthorityRecordType.DEVICE_REVOKE, null, true, true))
                .isEqualTo(Opposition.CANCELS);
    }

    @Test
    void aRecoveryUnderTheCommittedKeyCannotBeCancelledByADeviceOnlyExtendedOnce() {
        assertThat(policy.opposition(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, false, false)).isEqualTo(Opposition.EXTENDS_ONCE);
    }

    @Test
    void aRecoveryThroughAccountRecoveryIsVetoableImmediately() {
        assertThat(policy.opposition(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, false, false)).isEqualTo(Opposition.CANCELS);
    }

    @Test
    void aBearerSessionMayOnlyObjectToWhatItCanHonestlyObjectTo() {
        policy.requireSessionMayOppose(AuthorityRecordType.ADOPT_ROOT, null);
        policy.requireSessionMayOppose(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY);

        for (AuthorityRecordType type : new AuthorityRecordType[] { AuthorityRecordType.DEVICE_GRANT,
                AuthorityRecordType.DEVICE_REVOKE }) {
            assertThat(codeOf(() -> policy.requireSessionMayOppose(type, null)))
                    .isEqualTo("authority_opposition_device_required");
        }
    }

    @Test
    void aRecoveryKeyRecoveryRanksAboveDeviceRecordsAndAccountRecoveryBelow() {
        assertThat(policy.rankOf(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY)).isEqualTo((short) 2);
        assertThat(policy.rankOf(AuthorityRecordType.DEVICE_GRANT, null)).isEqualTo((short) 1);
        assertThat(policy.rankOf(AuthorityRecordType.ADOPT_ROOT, null)).isEqualTo((short) 1);
        assertThat(policy.rankOf(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY)).isEqualTo((short) 0);
    }

    @Test
    void aHigherRankRecordTakesTheSlotAndAnEqualOrLowerOneIsRefused() {
        assertThat(policy.resolveAgainstPending((short) 2, (short) 1)).isEqualTo(SlotOutcome.CANCELS_PENDING);
        assertThat(policy.resolveAgainstPending((short) 1, (short) 1)).isEqualTo(SlotOutcome.REFUSED);
        assertThat(policy.resolveAgainstPending((short) 0, (short) 1)).isEqualTo(SlotOutcome.REFUSED);
        assertThat(policy.resolveAgainstPending((short) 2, (short) 0)).isEqualTo(SlotOutcome.CANCELS_PENDING);
    }

    @Test
    void eachCancelledInitiationDoublesTheBackoffOfTheKeySetThatOpenedIt() {
        assertThat(policy.backoffAfter(0)).isEqualTo(Duration.ZERO);
        assertThat(policy.backoffAfter(1)).isEqualTo(Duration.ofHours(72));
        assertThat(policy.backoffAfter(2)).isEqualTo(Duration.ofHours(144));
        assertThat(policy.backoffAfter(3)).isEqualTo(Duration.ofHours(288));
        assertThat(policy.backoffAfter(9)).isEqualTo(policy.backoffAfter(4));
    }

    @Test
    void aLiveBackoffOrCooldownRefusesWithHowLongToWait() {
        Instant now = Instant.now();

        AuthorityTransitionException backoff = catchThrowableOfType(
                () -> policy.requireOutsideBackoff(now.plusSeconds(90), now), AuthorityTransitionException.class);
        AuthorityTransitionException cooldown = catchThrowableOfType(
                () -> policy.requireOutsideCooldown(now.plusSeconds(30),
                        AuthorityRecordType.ADOPT_ROOT.magic(), AuthorityRecordType.ADOPT_ROOT.magic(), now),
                AuthorityTransitionException.class);

        assertThat(backoff.getCode()).isEqualTo("authority_backoff");
        assertThat(backoff.getRetryAfterSeconds()).isEqualTo(90L);
        assertThat(cooldown.getCode()).isEqualTo("authority_cooldown");
        policy.requireOutsideBackoff(null, now);
        policy.requireOutsideCooldown(now.minusSeconds(1), AuthorityRecordType.ADOPT_ROOT.magic(),
                AuthorityRecordType.ADOPT_ROOT.magic(), now);
    }

    @Test
    void theCooldownRefusesTheShapeItWasWrittenForAndLeavesEveryOtherShapeAlone() {
        Instant now = Instant.now();
        Instant live = now.plusSeconds(30);

        assertThat(codeOf(() -> policy.requireOutsideCooldown(live, AuthorityRecordType.DEVICE_REVOKE.magic(),
                AuthorityRecordType.DEVICE_REVOKE.magic(), now))).isEqualTo("authority_cooldown");
        policy.requireOutsideCooldown(live, AuthorityRecordType.DEVICE_REVOKE.magic(),
                AuthorityRecordType.DEVICE_GRANT.magic(), now);
        policy.requireOutsideCooldown(live, AuthorityRecordType.DEVICE_REVOKE.magic(),
                AuthorityRecordType.AUTHORITY_RECOVERY.magic(), now);
        policy.requireOutsideCooldown(live, null, AuthorityRecordType.DEVICE_REVOKE.magic(), now);
    }

    @Test
    void theRecoveryKeyPathRunsTheRecoveryWindowAndEverythingElseRunsTheOppositionWindow() {
        assertThat(policy.windowFor(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY)).isEqualTo(Duration.ofDays(7));
        assertThat(policy.windowFor(AuthorityRecordType.AUTHORITY_RECOVERY,
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY)).isEqualTo(Duration.ofHours(72));
        assertThat(policy.windowFor(AuthorityRecordType.ADOPT_ROOT, null)).isEqualTo(Duration.ofHours(72));
    }

    private static ChainContext bootstrapEmpty() {
        return new ChainContext(true, false, false, 0);
    }

    private static String codeOf(Runnable action) {
        AuthorityTransitionException refusal =
                catchThrowableOfType(action::run, AuthorityTransitionException.class);
        assertThat(refusal).as("expected a refusal").isNotNull();
        return refusal.getCode();
    }
}
