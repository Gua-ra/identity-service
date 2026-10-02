package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

@ExtendWith(MockitoExtension.class)
class RegistrationGuardTest {

    // Real PhoneNumberNormalizer: both must be valid numbers, or it rejects them.
    private static final String UNKNOWN_PHONE = "+12025550123";
    private static final String ALLOWLISTED_PHONE = "+12025550199";

    @Mock
    private DirectoryService directoryService;
    @Mock
    private PhoneNumberHasher phoneNumberHasher;
    @Mock
    private MatrixAdminClient matrixAdminClient;

    private LoginFlowProperties properties;
    private RegistrationGuard guard;

    @BeforeEach
    void setUp() {
        properties = new LoginFlowProperties();
        properties.getRegistration().setWebAllowlistEnabled(true);
        properties.getRegistration().setWebAllowlist(List.of(ALLOWLISTED_PHONE));
        guard = new RegistrationGuard(properties, new PhoneNumberNormalizer(), directoryService,
                phoneNumberHasher, matrixAdminClient);
    }

    private static LoginSession session(String marker, String phone) {
        LoginSession session = new LoginSession();
        session.setDownstreamClient(marker);
        session.setPhoneNumber(phone);
        return session;
    }

    private static void assertNotApproved(ThrowingCallable call) {
        assertThatThrownBy(call)
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("status", HttpStatus.FORBIDDEN)
                .hasFieldOrPropertyWithValue("code", "registration_not_approved");
    }

    // --- Marker handling: only the exact native marker is exempt ------------

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "web", " ", "NATIVE", "Native", " native", "native ", "mobile", "web,native",
            "native,web" })
    void newUserWithWebAbsentOrUnrecognisedMarkerIsRefusedWhenNotAllowlisted(String marker) {
        assertNotApproved(() -> guard.assertAllowedForNewUser(session(marker, UNKNOWN_PHONE)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "web", "NATIVE", "mobile", "web,native" })
    void newUserWithWebAbsentOrUnrecognisedMarkerIsAllowedWhenAllowlisted(String marker) {
        assertThatCode(() -> guard.assertAllowedForNewUser(session(marker, ALLOWLISTED_PHONE)))
                .doesNotThrowAnyException();
    }

    @Test
    void newUserWithExactNativeMarkerIsExempt() {
        assertThatCode(() -> guard.assertAllowedForNewUser(session("native", UNKNOWN_PHONE)))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "web", " ", "NATIVE", "Native", "mobile", "web,native" })
    void otpWithWebAbsentOrUnrecognisedMarkerIsRefusedForUnknownNumber(String marker) {
        // Unstubbed lookups return Optional.empty(): no account for this number.
        assertNotApproved(() -> guard.assertOtpAllowed(session(marker, null), UNKNOWN_PHONE));
    }

    @Test
    void otpWithExactNativeMarkerIsExemptForUnknownNumber() {
        assertThatCode(() -> guard.assertOtpAllowed(session("native", null), UNKNOWN_PHONE))
                .doesNotThrowAnyException();

        verifyNoInteractions(directoryService, phoneNumberHasher, matrixAdminClient);
    }

    @Test
    void otpWithWebMarkerIsAllowedForExistingAccount() {
        when(phoneNumberHasher.digest(UNKNOWN_PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest"))
                .thenReturn(Optional.of(DirectoryEntry.builder().phoneDigest("digest").userId("@a:gua.local").build()));

        assertThatCode(() -> guard.assertOtpAllowed(session("web", null), UNKNOWN_PHONE))
                .doesNotThrowAnyException();
    }

    @Test
    void configuredNativeMarkerReplacesTheDefault() {
        properties.getRegistration().setNativeClientMarker("app");

        assertThatCode(() -> guard.assertAllowedForNewUser(session("app", UNKNOWN_PHONE)))
                .doesNotThrowAnyException();
        assertNotApproved(() -> guard.assertAllowedForNewUser(session("native", UNKNOWN_PHONE)));
    }

    // --- Sessionless REST entry points: always web -------------------------

    @Test
    void restNewUserIsRefusedWhenNotAllowlisted() {
        assertNotApproved(() -> guard.assertAllowedForNewUser(UNKNOWN_PHONE));
    }

    @Test
    void restNewUserIsAllowedWhenAllowlisted() {
        assertThatCode(() -> guard.assertAllowedForNewUser(ALLOWLISTED_PHONE)).doesNotThrowAnyException();
    }

    @Test
    void restOtpIsRefusedForUnknownNumber() {
        assertNotApproved(() -> guard.assertOtpAllowed(UNKNOWN_PHONE));
    }

    // --- Flag off: nothing changes -----------------------------------------

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "web", "native", "mobile" })
    void gateOffIsANoOpForEveryMarker(String marker) {
        properties.getRegistration().setWebAllowlistEnabled(false);

        assertThatCode(() -> {
            guard.assertOtpAllowed(session(marker, null), UNKNOWN_PHONE);
            guard.assertAllowedForNewUser(session(marker, UNKNOWN_PHONE));
            guard.assertOtpAllowed(UNKNOWN_PHONE);
            guard.assertAllowedForNewUser(UNKNOWN_PHONE);
        }).doesNotThrowAnyException();

        verifyNoInteractions(directoryService, phoneNumberHasher, matrixAdminClient);
    }
}
