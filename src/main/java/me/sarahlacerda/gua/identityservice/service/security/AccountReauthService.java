package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.service.OtpService;

/**
 * Orchestrates the OTP-based reauthentication flow used to gate sensitive
 * account operations
 * (deactivate, identity reset). Mirrors the spirit of the Matrix
 * {@code m.login.msisdn} UIA stage
 * — the caller is already authenticated for the active session but must prove
 * possession of the
 * registered phone before we honour the request.
 *
 * <p>
 * Two-step interface so the client UI can show progress between SMS send and
 * code entry:
 * <ol>
 * <li>{@link #startReauth(String)} — sends a fresh OTP to the user's linked
 * phone.</li>
 * <li>{@link #verifyReauth(String, String)} — exchanges the code for a
 * single-use reauth token
 * the caller spends on a privileged endpoint (e.g.
 * {@code /account/deactivate}).</li>
 * </ol>
 */
@Service
@RequiredArgsConstructor
public class AccountReauthService {

    private static final Logger log = LoggerFactory.getLogger(AccountReauthService.class);

    private final OtpService otpService;
    private final MatrixAdminClient matrixAdminClient;
    private final ReauthTokenService reauthTokenService;

    public void startReauth(String userId, String requesterIp, String language) {
        String phone = resolveLinkedPhone(userId);
        otpService.sendOtp(phone, requesterIp, language);
        log.info("Issued reauth OTP for {}", userId);
    }

    public String verifyReauth(String userId, String code, ReauthOperation operation) {
        String phone = resolveLinkedPhone(userId);
        otpService.verifyOtp(phone, code);
        String token = reauthTokenService.issue(userId, operation);
        log.info("Issued {} reauth token for {}", operation, userId);
        return token;
    }

    public void requireValidReauth(String userId, String reauthToken, ReauthOperation operation) {
        if (reauthToken == null || reauthToken.isBlank()) {
            throw new InvalidReauthTokenException("Reauth token required");
        }
        reauthTokenService.consume(reauthToken, userId, operation);
    }

    /**
     * Returns the first MSISDN linked to {@code userId} on the homeserver. We could
     * later persist
     * a separate phone-per-user mapping but the Matrix admin API already owns this
     * for us.
     */
    private String resolveLinkedPhone(String userId) {
        List<String> phones = matrixAdminClient.getLinkedPhones(userId);
        if (phones.isEmpty()) {
            throw new UnknownUserException("No phone number linked to account " + userId.toLowerCase(Locale.ROOT));
        }
        return phones.get(0);
    }
}
