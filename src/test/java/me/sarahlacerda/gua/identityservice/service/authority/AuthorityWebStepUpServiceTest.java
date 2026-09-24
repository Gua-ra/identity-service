// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;

/**
 * The step-up a transition can take in the web sheet, driven against a real repository (ADM-009 decision 4
 * step 2).
 *
 * <p>What is worth pinning here is not that a row can be written. It is the four bindings and the single use:
 * a proof taken by one account, from one access token, for one transition, inside the challenge's own life,
 * spendable exactly once. Every one of those is what stops this being a way to arrange an authority proof
 * somewhere and spend it somewhere else.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class AuthorityWebStepUpServiceTest {

    private static final String USER = "@sarah:gua.global";
    private static final String OTHER_USER = "@someone:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final String OTHER_SESSION = "b".repeat(64);
    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");
    /** Long past any hold, so nothing here is refused for the age of the credential. */
    private static final Instant LONG_AGO = NOW.minus(Duration.ofDays(400));

    @Autowired
    private AuthorityWebStepUpRepository repository;

    private IdentityServiceProperties properties;
    private AuthorityPolicy policy;
    private AuthorityWebStepUpService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().setNativeClientIds(java.util.List.of("gua-android"));
        policy = new AuthorityPolicy(properties, mock(UserSecurityService.class));
        service = new AuthorityWebStepUpService(repository, policy,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void aProofTakenInTheSheetIsSpentOnceAndThenGone() {
        Instant expiresAt = service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO);

        // The challenge's own life, so a sheet left open in a background tab is not a step-up an hour later.
        assertThat(expiresAt).isEqualTo(NOW.plus(properties.getAuthority().getChallengeTtl()));

        Optional<AuthorityWebStepUpService.Proved> first = service.consume(USER, SESSION, Purpose.ADOPT);
        assertThat(first).isPresent();
        assertThat(first.get().factor()).isEqualTo(AuthFactor.PASSKEY);
        // The age travels with the proof, so the fresh-factor hold weighs the credential that was presented
        // rather than whatever the account happens to hold by the time the record arrives.
        assertThat(first.get().factorCreatedAt()).isEqualTo(LONG_AGO);

        assertThat(service.consume(USER, SESSION, Purpose.ADOPT)).isEmpty();
    }

    @Test
    void aProofForOneTransitionIsNotAProofForAnother() {
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO);

        // O9 asks for a possession proof of this transition. Confirming an adoption must not also hand over
        // the device set.
        assertThat(service.consume(USER, SESSION, Purpose.GRANT)).isEmpty();
        assertThat(service.consume(USER, SESSION, Purpose.REVOKE)).isEmpty();
        assertThat(service.consume(USER, SESSION, Purpose.RECOVER)).isEmpty();
        // And the refused lookups left it alone.
        assertThat(service.consume(USER, SESSION, Purpose.ADOPT)).isPresent();
    }

    @Test
    void aProofIsNotSpendableByAnotherSessionOrAnotherAccount() {
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PIN, LONG_AGO);

        // A stolen bearer token of the same account is a different session, and this is the binding that
        // makes it one.
        assertThat(service.consume(USER, OTHER_SESSION, Purpose.ADOPT)).isEmpty();
        assertThat(service.consume(OTHER_USER, SESSION, Purpose.ADOPT)).isEmpty();
        assertThat(service.consume(USER, SESSION, Purpose.ADOPT)).isPresent();
    }

    @Test
    void aProofOlderThanTheChallengeIsNotAProof() {
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO);

        AuthorityWebStepUpService later = new AuthorityWebStepUpService(repository, policy,
                Clock.fixed(NOW.plus(properties.getAuthority().getChallengeTtl()).plusSeconds(1), ZoneOffset.UTC));
        assertThat(later.consume(USER, SESSION, Purpose.ADOPT)).isEmpty();
    }

    @Test
    void takingTheSheetTwiceLeavesOneProofRatherThanTwo() {
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PIN, LONG_AGO);
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO);

        // One transition, one proof. Two live ones would mean a caller could run the sheet twice and keep a
        // spare, which is the shape of every single-use control that turned out not to be one.
        Optional<AuthorityWebStepUpService.Proved> spent = service.consume(USER, SESSION, Purpose.ADOPT);
        assertThat(spent).isPresent();
        assertThat(spent.get().factor()).isEqualTo(AuthFactor.PASSKEY);
        assertThat(service.consume(USER, SESSION, Purpose.ADOPT)).isEmpty();
    }

    @Test
    void nothingButThePasskeyAndThePinMayEverBeRecorded() {
        // Decision 9 at its widest, stated where the row is written. There is no arm of the page that sends a
        // code, so the only way to reach this is an edit that adds one, and it fails here as well as in the
        // guard test.
        assertThatThrownBy(() -> service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PHONE_OTP, LONG_AGO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(repository.count()).isZero();
    }

    @Test
    void onlyATransitionThatAsksForAFactorGetsASheet() {
        service.requireMayOpen(Optional.of("gua-android"), Purpose.ADOPT);
        service.requireMayOpen(Optional.of("gua-android"), Purpose.GRANT);
        service.requireMayOpen(Optional.of("gua-android"), Purpose.REVOKE);
        service.requireMayOpen(Optional.of("gua-android"), Purpose.RECOVER);

        for (Purpose purpose : new Purpose[] { Purpose.APPROVE, Purpose.OPPOSE, Purpose.NOTIFY }) {
            assertThat(refusalFor(() -> service.requireMayOpen(Optional.of("gua-android"), purpose)))
                    .as("%s", purpose)
                    .isEqualTo("authority_step_up_purpose_refused");
        }
    }

    @Test
    void theBrowserCannotOpenOneOfTheseForItself() {
        // Decision 6 is a rule, not a default. A sheet a web session opened for itself would be a browser
        // arranging its own authority proof, which is the one thing that record forbids outright.
        assertThat(refusalFor(() -> service.requireMayOpen(Optional.of("gua-web"), Purpose.ADOPT)))
                .isEqualTo("authority_native_session_required");
        assertThat(refusalFor(() -> service.requireMayOpen(Optional.empty(), Purpose.ADOPT)))
                .isEqualTo("authority_native_session_required");
    }

    @Test
    void aStampedPurposeThatCannotBeReadBackIsRefusedRatherThanGuessed() {
        assertThat(refusalFor(() -> service.requireOpen("NOT_A_PURPOSE")))
                .isEqualTo("authority_step_up_purpose_refused");
        assertThat(refusalFor(() -> service.requireOpen(null)))
                .isEqualTo("authority_step_up_purpose_refused");
    }

    @Test
    void withTheFlagOffNothingIsOpenedAndNothingIsSpent() {
        properties.getAuthority().setEnabled(false);

        assertThat(refusalFor(() -> service.requireMayOpen(Optional.of("gua-android"), Purpose.ADOPT)))
                .isEqualTo("authority_disabled");
        assertThat(refusalFor(() -> service.requireOpen("ADOPT"))).isEqualTo("authority_disabled");
        assertThat(refusalFor(() -> service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO)))
                .isEqualTo("authority_disabled");
        assertThat(repository.count()).isZero();

        // And a row written while it was on is inert while it is off, so switching the feature back off is a
        // way back and not a state where half a transition is still spendable.
        properties.getAuthority().setEnabled(true);
        service.proved(USER, SESSION, Purpose.ADOPT, AuthFactor.PASSKEY, LONG_AGO);
        properties.getAuthority().setEnabled(false);
        assertThat(service.consume(USER, SESSION, Purpose.ADOPT)).isEmpty();
    }

    private static String refusalFor(Runnable call) {
        AuthorityTransitionException refusal = catchThrowableOfType(call::run, AuthorityTransitionException.class);
        assertThat(refusal).as("a refusal was expected").isNotNull();
        return refusal.getCode();
    }
}
