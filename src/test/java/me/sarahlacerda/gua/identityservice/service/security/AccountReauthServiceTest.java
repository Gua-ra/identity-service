package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.service.OtpService;

@ExtendWith(MockitoExtension.class)
class AccountReauthServiceTest {

    @Mock
    private OtpService otpService;

    @Mock
    private MatrixAdminClient matrixAdminClient;

    @Mock
    private ReauthTokenService reauthTokenService;

    private AccountReauthService service;

    @BeforeEach
    void setUp() {
        service = new AccountReauthService(otpService, matrixAdminClient, reauthTokenService);
    }

    @Test
    void startReauthSendsOtpToLinkedPhone() {
        when(matrixAdminClient.getLinkedPhones("@alice:server")).thenReturn(List.of("+12025550123"));

        service.startReauth("@alice:server", "1.2.3.4", "en-US");

        verify(otpService).sendOtp("+12025550123", "1.2.3.4", "en-US");
    }

    @Test
    void startReauthFailsWhenNoPhoneLinked() {
        when(matrixAdminClient.getLinkedPhones("@alice:server")).thenReturn(List.of());

        assertThatThrownBy(() -> service.startReauth("@alice:server", "1.2.3.4", null))
                .isInstanceOf(UnknownUserException.class);
        verifyNoInteractions(otpService);
    }

    @Test
    void verifyReauthIssuesTokenAfterOtpVerified() {
        when(matrixAdminClient.getLinkedPhones("@alice:server")).thenReturn(List.of("+12025550123"));
        when(reauthTokenService.issue("@alice:server", ReauthOperation.PHONE_CHANGE)).thenReturn("opaque-token");

        String token = service.verifyReauth("@alice:server", "123456", ReauthOperation.PHONE_CHANGE);

        verify(otpService).verifyOtp("+12025550123", "123456");
        assertThat(token).isEqualTo("opaque-token");
    }

    @Test
    void verifyReauthDoesNotIssueTokenWhenOtpInvalid() {
        when(matrixAdminClient.getLinkedPhones("@alice:server")).thenReturn(List.of("+12025550123"));
        org.mockito.Mockito.doThrow(new InvalidOtpException("bad"))
                .when(otpService).verifyOtp(eq("+12025550123"), eq("000000"));

        assertThatThrownBy(() -> service.verifyReauth("@alice:server", "000000", ReauthOperation.DEACTIVATE))
                .isInstanceOf(InvalidOtpException.class);
        verifyNoInteractions(reauthTokenService);
    }

    @Test
    void requireValidReauthDelegatesToTokenService() {
        when(reauthTokenService.consume("opaque-token", "@alice:server", ReauthOperation.PHONE_CHANGE))
                .thenReturn("@alice:server");

        service.requireValidReauth("@alice:server", "opaque-token", ReauthOperation.PHONE_CHANGE);

        verify(reauthTokenService).consume("opaque-token", "@alice:server", ReauthOperation.PHONE_CHANGE);
    }

    @Test
    void requireValidReauthRejectsBlankToken() {
        assertThatThrownBy(() -> service.requireValidReauth("@alice:server", " ", ReauthOperation.PHONE_CHANGE))
                .isInstanceOf(InvalidReauthTokenException.class);
        verifyNoInteractions(reauthTokenService);
    }
}
