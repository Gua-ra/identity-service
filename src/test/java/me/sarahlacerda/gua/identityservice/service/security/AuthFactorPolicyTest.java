package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthFactorPolicyTest {

    private static final String USER = "@alice:example.test";

    @Mock
    private UserSecurityService userSecurityService;
    @Mock
    private PasskeyService passkeyService;

    private AuthFactorPolicy policy() {
        return new AuthFactorPolicy(userSecurityService, passkeyService);
    }

    @Test
    void aPasskeyCountsAsRegisteredOnlyWhenTheDeploymentCanActuallyAssertIt() {
        when(passkeyService.isEnabled()).thenReturn(false);

        assertThat(policy().passkeyRegistered(USER)).isFalse();
    }

    @Test
    void passkeysSupportedReportsTheDeploymentAndAsksNothingAboutTheAccount() {
        when(passkeyService.isEnabled()).thenReturn(true);

        assertThat(policy().passkeysSupported()).isTrue();

        org.mockito.Mockito.verify(passkeyService, org.mockito.Mockito.never()).hasPasskey(
                org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verifyNoInteractions(userSecurityService);
    }

    @Test
    void passkeysAreUnsupportedWhenTheDeploymentHasThemSwitchedOff() {
        when(passkeyService.isEnabled()).thenReturn(false);

        assertThat(policy().passkeysSupported()).isFalse();
    }

    @Test
    void preferredFactorRanksPasskeyThenPinThenPhone() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);

        assertThat(policy().preferredFactor(USER)).isEqualTo(AuthFactor.PASSKEY);
    }

    @Test
    void preferredFactorIsThePinWhenThereIsNoPasskey() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(false);
        when(userSecurityService.hasPin(USER)).thenReturn(true);

        assertThat(policy().preferredFactor(USER)).isEqualTo(AuthFactor.PIN);
    }

    @Test
    void preferredFactorFallsBackToThePhoneEveryAccountAlreadyHas() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(false);
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        assertThat(policy().preferredFactor(USER)).isEqualTo(AuthFactor.PHONE_OTP);
    }

    @Test
    void anAccountHoldingAPinIsAskedForItAndMayPresentItsPasskeyInstead() {
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(true);

        AuthFactorPolicy.LoginPolicy withBoth = policy().loginPolicy(USER);

        assertThat(withBoth.pinStepRequired()).isTrue();
        assertThat(withBoth.passkeyRequired()).isFalse();
        assertThat(withBoth.factorSetupRequired()).isFalse();
        assertThat(withBoth.completesWith(AuthFactor.PIN)).isTrue();
        assertThat(withBoth.completesWith(AuthFactor.PASSKEY)).isTrue();
    }

    @Test
    void anAccountHoldingOnlyAPasskeyMustPresentIt() {
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        AuthFactorPolicy.LoginPolicy passkeyOnly = policy().loginPolicy(USER);

        assertThat(passkeyOnly.passkeyRequired()).isTrue();
        assertThat(passkeyOnly.pinStepRequired()).isFalse();
        assertThat(passkeyOnly.factorSetupRequired()).isFalse();
        assertThat(passkeyOnly.completesWith(AuthFactor.PASSKEY)).isTrue();
        assertThat(passkeyOnly.completesWith(AuthFactor.PIN)).isFalse();
    }

    @Test
    void anAccountHoldingNothingMustSetUpAFactor() {
        when(passkeyService.hasPasskey(USER)).thenReturn(false);
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        AuthFactorPolicy.LoginPolicy nothing = policy().loginPolicy(USER);

        assertThat(nothing.factorSetupRequired()).isTrue();
        assertThat(nothing.pinStepRequired()).isFalse();
        assertThat(nothing.passkeyRequired()).isFalse();
    }

    @Test
    void thePhoneCodeNeverCompletesASignIn() {
        for (boolean passkey : new boolean[] { true, false }) {
            for (boolean pin : new boolean[] { true, false }) {
                assertThat(new AuthFactorPolicy.LoginPolicy(passkey, pin).completesWith(AuthFactor.PHONE_OTP))
                        .as("passkey=%s pin=%s", passkey, pin)
                        .isFalse();
            }
        }
    }

    @Test
    void aStoredPasskeyStillGatesSignInWhenTheDeploymentHasPasskeysSwitchedOff() {
        lenient().when(passkeyService.isEnabled()).thenReturn(false);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        AuthFactorPolicy policy = policy();

        assertThat(policy.passkeyHeld(USER)).isTrue();
        assertThat(policy.passkeyRegistered(USER)).isFalse();
        assertThat(policy.loginPolicy(USER).passkeyRequired()).isTrue();
        assertThat(policy.loginPolicy(USER).factorSetupRequired()).isFalse();
    }

    @Test
    void thePhoneChangeAcceptsThePasskeyAheadOfThePinAndNothingElse() {
        AuthFactorPolicy.StepUpPolicy stepUp = policy().stepUpFor(ReauthOperation.PHONE_CHANGE);

        assertThat(stepUp.accepted()).containsExactly(AuthFactor.PASSKEY, AuthFactor.PIN);
        assertThat(stepUp.outranks(AuthFactor.PASSKEY, AuthFactor.PIN)).isTrue();
        assertThat(stepUp.outranks(AuthFactor.PIN, AuthFactor.PASSKEY)).isFalse();
        assertThat(stepUp.accepts(AuthFactor.PHONE_OTP)).isFalse();
        assertThat(stepUp.hardBlockWhenUnsatisfied()).isTrue();
    }

    @Test
    void theAcceptedFactorsDoNotNarrowToWhatTheAccountHappensToHold() {
        AuthFactorPolicy policy = policy();

        assertThat(policy.stepUpFor(ReauthOperation.PHONE_CHANGE).accepts(AuthFactor.PIN)).isTrue();
        assertThat(policy.stepUpFor(ReauthOperation.PHONE_CHANGE).accepts(AuthFactor.PASSKEY)).isTrue();
        assertThat(policy.stepUpFor(ReauthOperation.PHONE_CHANGE))
                .isEqualTo(policy.stepUpFor(ReauthOperation.PHONE_CHANGE));
    }

    @Test
    void outranksNeverInventsAWayThroughThatTheOperationDoesNotAccept() {
        AuthFactorPolicy.StepUpPolicy stepUp = policy().stepUpFor(ReauthOperation.PHONE_CHANGE);

        assertThat(stepUp.outranks(AuthFactor.PHONE_OTP, AuthFactor.PIN)).isFalse();
        assertThat(stepUp.outranks(AuthFactor.PASSKEY, AuthFactor.PHONE_OTP)).isFalse();
    }

    @Test
    void deactivateAndIdentityResetAreReportedAsTheyAreActuallyEnforced() {
        AuthFactorPolicy policy = policy();

        assertThat(policy.stepUpFor(ReauthOperation.DEACTIVATE).accepted())
                .containsExactly(AuthFactor.PHONE_OTP);
        assertThat(policy.stepUpFor(ReauthOperation.IDENTITY_RESET).accepted())
                .containsExactly(AuthFactor.PHONE_OTP);
        assertThat(policy.stepUpFor(ReauthOperation.DEACTIVATE).hardBlockWhenUnsatisfied()).isFalse();
    }

    @Test
    void recoveryIsTheSamePathWhetherOrNotTheAccountHoldsAPasskey() {
        when(passkeyService.hasPasskey(USER)).thenReturn(true);

        AuthFactorPolicy.RecoveryPolicy withPasskey = policy().recoveryFor(USER);

        assertThat(withPasskey.restores()).isEqualTo(AuthFactor.PIN);
        assertThat(withPasskey.provenBy()).isEqualTo(AuthFactor.PHONE_OTP);
        assertThat(withPasskey.removesPasskeys()).isTrue();
    }

    @Test
    void recoveryForAnAccountWithNoPasskeyReportsTheSameRestoreAndProof() {
        when(passkeyService.hasPasskey(USER)).thenReturn(false);

        AuthFactorPolicy.RecoveryPolicy withoutPasskey = policy().recoveryFor(USER);

        assertThat(withoutPasskey.restores()).isEqualTo(AuthFactor.PIN);
        assertThat(withoutPasskey.provenBy()).isEqualTo(AuthFactor.PHONE_OTP);
        assertThat(withoutPasskey.removesPasskeys()).isFalse();
    }
}
