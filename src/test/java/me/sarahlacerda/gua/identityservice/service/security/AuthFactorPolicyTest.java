package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The component every factor decision now goes through, so these are the answers login,
 * the phone-change step-up and recovery all get.
 *
 * <p>
 * Most of what is frozen here is what the policy must NOT do. The dangerous edits in this
 * area all look reasonable in isolation: narrow an operation's accepted factors by what the
 * account holds, let a registered passkey stand in for the PIN step, refuse recovery to an
 * account that has a stronger factor. Each of them turns a credential that has quietly
 * become unusable into an account with no way in at all, and this service has no way to
 * remove or replace a registered credential.
 */
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

    // -------------------- registered factors --------------------

    @Test
    void aPasskeyCountsAsRegisteredOnlyWhenTheDeploymentCanActuallyAssertIt() {
        when(passkeyService.isEnabled()).thenReturn(false);

        // A stored credential on a deployment with passkeys switched off is a factor nobody
        // can produce, so reporting it would offer a way in that does not exist.
        assertThat(policy().passkeyRegistered(USER)).isFalse();
    }

    /**
     * Deployment capability, not account state. It is the one sense in which a passkey can be
     * "unavailable" that the server settles on its own, which is exactly why signup may act on
     * it: nobody asserted it, it was read from configuration.
     */
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

    // -------------------- login --------------------

    @Test
    void aRegisteredPasskeyNeitherAddsNorRemovesThePinStep() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(true);

        AuthFactorPolicy.LoginPolicy withBoth = policy().loginPolicy(USER);

        // Preferred moves to the passkey, the PIN step does not move. Skipping it would let
        // possession of a device stand in for knowledge on the permissive login side.
        assertThat(withBoth.preferred()).isEqualTo(AuthFactor.PASSKEY);
        assertThat(withBoth.pinStepRequired()).isTrue();
        assertThat(withBoth.allows(AuthFactor.PIN)).isTrue();
        assertThat(withBoth.allows(AuthFactor.PHONE_OTP)).isTrue();
    }

    @Test
    void anAccountWithAPasskeyAndNoPinIsNotForcedThroughAPinStep() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(false);

        AuthFactorPolicy.LoginPolicy loginPolicy = policy().loginPolicy(USER);

        // The other half of the same rule: a registered passkey must not make the PIN
        // mandatory either, or an account whose credential broke would have nothing to offer.
        assertThat(loginPolicy.pinStepRequired()).isFalse();
        assertThat(loginPolicy.fallbacks()).containsExactly(AuthFactor.PHONE_OTP);
    }

    @Test
    void loginKeepsThePhoneFallbackForEveryAccount() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        when(userSecurityService.hasPin(USER)).thenReturn(true);

        assertThat(policy().loginPolicy(USER).fallbacks())
                .containsExactly(AuthFactor.PIN, AuthFactor.PHONE_OTP);
    }

    // -------------------- step-up --------------------

    @Test
    void thePhoneChangeAcceptsThePasskeyAheadOfThePinAndNothingElse() {
        AuthFactorPolicy.StepUpPolicy stepUp = policy().stepUpFor(ReauthOperation.PHONE_CHANGE);

        assertThat(stepUp.accepted()).containsExactly(AuthFactor.PASSKEY, AuthFactor.PIN);
        assertThat(stepUp.outranks(AuthFactor.PASSKEY, AuthFactor.PIN)).isTrue();
        assertThat(stepUp.outranks(AuthFactor.PIN, AuthFactor.PASSKEY)).isFalse();
        // The reauth token proves a code sent to the number being re-pointed, so it cannot
        // carry this operation on its own.
        assertThat(stepUp.accepts(AuthFactor.PHONE_OTP)).isFalse();
        assertThat(stepUp.hardBlockWhenUnsatisfied()).isTrue();
    }

    @Test
    void theAcceptedFactorsDoNotNarrowToWhatTheAccountHappensToHold() {
        AuthFactorPolicy policy = policy();

        // stepUpFor takes no account: an account with only a PIN still sees PASSKEY accepted,
        // and one with only a passkey still sees PIN accepted. Narrowing the set to what an
        // account holds is how a bare existence check becomes a lockout, because the factor it
        // narrowed to is exactly the one that may have become unusable.
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

        // Recorded, not endorsed. Both are reauth-token-only today, which is weaker than the
        // phone change, and saying so in one readable place is the point: the gap used to be
        // visible only as the absence of a check.
        assertThat(policy.stepUpFor(ReauthOperation.DEACTIVATE).accepted())
                .containsExactly(AuthFactor.PHONE_OTP);
        assertThat(policy.stepUpFor(ReauthOperation.IDENTITY_RESET).accepted())
                .containsExactly(AuthFactor.PHONE_OTP);
        assertThat(policy.stepUpFor(ReauthOperation.DEACTIVATE).hardBlockWhenUnsatisfied()).isFalse();
    }

    // -------------------- recovery --------------------

    @Test
    void recoveryIsTheSamePathWhetherOrNotTheAccountHoldsAPasskey() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(true);

        AuthFactorPolicy.RecoveryPolicy withPasskey = policy().recoveryFor(USER);

        // The stronger factor is reported and NOT applied. Applying it would mean an account
        // whose passkey broke has no login and no recovery, which is a worse failure than the
        // one it would be closing, and closing it properly needs a protocol that can prove the
        // passkey is really gone.
        assertThat(withPasskey.restores()).isEqualTo(AuthFactor.PIN);
        assertThat(withPasskey.provenBy()).isEqualTo(AuthFactor.PHONE_OTP);
        assertThat(withPasskey.accountAlsoHoldsPasskey()).isTrue();
    }

    @Test
    void recoveryForAnAccountWithNoPasskeyReportsTheSameRestoreAndProof() {
        when(passkeyService.isEnabled()).thenReturn(true);
        when(passkeyService.hasPasskey(USER)).thenReturn(false);

        AuthFactorPolicy.RecoveryPolicy withoutPasskey = policy().recoveryFor(USER);

        assertThat(withoutPasskey.restores()).isEqualTo(AuthFactor.PIN);
        assertThat(withoutPasskey.provenBy()).isEqualTo(AuthFactor.PHONE_OTP);
        assertThat(withoutPasskey.accountAlsoHoldsPasskey()).isFalse();
    }

    @Test
    void recordingARecoveryRequestNeverRefusesIt() {
        lenient().when(passkeyService.isEnabled()).thenReturn(true);
        lenient().when(passkeyService.hasPasskey(USER)).thenReturn(true);

        // It leaves a line behind and returns. If this ever starts throwing, recovery has been
        // gated on holding a stronger factor and the lockout above is back.
        assertThatCode(() -> policy().recordRecoveryRequest(USER)).doesNotThrowAnyException();
    }
}
