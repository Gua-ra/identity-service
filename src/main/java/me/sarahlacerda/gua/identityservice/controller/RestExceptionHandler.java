package me.sarahlacerda.gua.identityservice.controller;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import me.sarahlacerda.gua.identityservice.account.authority.InvalidAuthorityRecordException;
import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryCooldownException;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryNotReadyException;
import me.sarahlacerda.gua.identityservice.exception.EndpointRetiredException;
import me.sarahlacerda.gua.identityservice.exception.GenesisRegistrationException;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinChallengeException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.InvalidSignupTokenException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.InvalidUsernameException;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.exception.OidcClientAuthenticationException;
import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneChangeChallengeException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.PhoneChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.ReauthPhoneMismatchException;
import me.sarahlacerda.gua.identityservice.exception.StepUpRequiredException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import me.sarahlacerda.gua.identityservice.exception.WeakPinException;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryState;

@RestControllerAdvice
public class RestExceptionHandler {

        private static final Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);

        @ExceptionHandler({ RedisConnectionFailureException.class, DataAccessResourceFailureException.class })
        public ResponseEntity<ErrorResponse> handleBackingStoreUnavailable(RuntimeException ex) {
                log.error("Backing store unavailable: {}", ex.getMessage());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .header("Retry-After", "30")
                                .body(new ErrorResponse("service_unavailable", "Service temporarily unavailable"));
        }

        @ExceptionHandler(InvalidOtpException.class)
        public ResponseEntity<ErrorResponse> handleInvalidOtp(InvalidOtpException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_otp", ex.getMessage()));
        }

        @ExceptionHandler({ OtpRateLimitedException.class, RateLimiterException.class })
        public ResponseEntity<ErrorResponse> handleRateLimited(RuntimeException ex) {
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(new ErrorResponse("rate_limited", ex.getMessage()));
        }

        @ExceptionHandler(PhoneAlreadyLinkedException.class)
        public ResponseEntity<ErrorResponse> handlePhoneAlreadyLinked(PhoneAlreadyLinkedException ex) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                                .body(new ErrorResponse("phone_already_linked", ex.getMessage()));
        }

        @ExceptionHandler(InvalidSignupTokenException.class)
        public ResponseEntity<ErrorResponse> handleInvalidSignupToken(InvalidSignupTokenException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(new ErrorResponse("invalid_signup_token", ex.getMessage()));
        }

        @ExceptionHandler(InvalidUsernameException.class)
        public ResponseEntity<ErrorResponse> handleInvalidUsername(InvalidUsernameException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_username", ex.getMessage()));
        }

        @ExceptionHandler(InvalidPhoneNumberException.class)
        public ResponseEntity<ErrorResponse> handleInvalidPhoneNumber(InvalidPhoneNumberException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_phone_number", ex.getMessage()));
        }

        @ExceptionHandler(UsernameTakenException.class)
        public ResponseEntity<ErrorResponse> handleUsernameTaken(UsernameTakenException ex) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                                .body(new ErrorResponse("username_taken", ex.getMessage()));
        }

        @ExceptionHandler(me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException.class)
        public ResponseEntity<ErrorResponse> handleLookupBatchTooLarge(
                        me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("lookup_batch_too_large", ex.getMessage()));
        }

        @ExceptionHandler(WeakPinException.class)
        public ResponseEntity<ErrorResponse> handleWeakPin(WeakPinException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("weak_pin", ex.getMessage()));
        }

        @ExceptionHandler(InvalidPinException.class)
        public ResponseEntity<ErrorResponse> handleInvalidPin(InvalidPinException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_pin", ex.getMessage()));
        }

        @ExceptionHandler(InvalidPinOperationException.class)
        public ResponseEntity<ErrorResponse> handlePinOperation(InvalidPinOperationException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("pin_error", ex.getMessage()));
        }

        @ExceptionHandler(InvalidPinChallengeException.class)
        public ResponseEntity<ErrorResponse> handleInvalidPinChallenge(InvalidPinChallengeException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(new ErrorResponse("invalid_pin_challenge", ex.getMessage()));
        }

        @ExceptionHandler(me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException.class)
        public ResponseEntity<ErrorResponse> handleInvalidReauthToken(
                        me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(new ErrorResponse("invalid_reauth_token", ex.getMessage()));
        }

        @ExceptionHandler(PinLockedException.class)
        public ResponseEntity<ErrorResponse> handlePinLocked(PinLockedException ex) {
                String message = ex.getRemainingSeconds() > 0
                                ? ex.getMessage() + " (retry in " + ex.getRemainingSeconds() + "s)"
                                : ex.getMessage();
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(new ErrorResponse("pin_locked", message));
        }

        @ExceptionHandler(PinChangeCooldownException.class)
        public ResponseEntity<ErrorResponse> handlePinChangeCooldown(PinChangeCooldownException ex) {
                String message = ex.getRemainingSeconds() > 0
                                ? ex.getMessage() + " (retry in " + ex.getRemainingSeconds() + "s)"
                                : ex.getMessage();
                return ResponseEntity.status(HttpStatus.TOO_EARLY)
                                .header("Retry-After", String.valueOf(Math.max(ex.getRemainingSeconds(), 1)))
                                .body(new ErrorResponse("pin_change_cooldown", message));
        }

        @ExceptionHandler(PinChangeChallengeNotFoundException.class)
        public ResponseEntity<ErrorResponse> handlePinChangeChallenge(PinChangeChallengeNotFoundException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(new ErrorResponse("pin_change_challenge_invalid", ex.getMessage()));
        }

        @ExceptionHandler(InvalidPhoneChangeChallengeException.class)
        public ResponseEntity<ErrorResponse> handlePhoneChangeChallenge(InvalidPhoneChangeChallengeException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(new ErrorResponse("phone_change_challenge_invalid", ex.getMessage()));
        }

        @ExceptionHandler(PhoneChangeCooldownException.class)
        public ResponseEntity<ErrorResponse> handlePhoneChangeCooldown(PhoneChangeCooldownException ex) {
                String message = ex.getRemainingSeconds() > 0
                                ? ex.getMessage() + " (retry in " + ex.getRemainingSeconds() + "s)"
                                : ex.getMessage();
                return ResponseEntity.status(HttpStatus.TOO_EARLY)
                                .header("Retry-After", String.valueOf(Math.max(ex.getRemainingSeconds(), 1)))
                                .body(new ErrorResponse("phone_change_cooldown", message));
        }

        /**
         * The fresh-2FA hold: the account PIN is too new to be spent as the phone-change
         * step-up factor. Answered as 400 with {@code twofa_cooldown_active} and the
         * remaining seconds in the body, which is the shape both clients already parse;
         * {@code Retry-After} carries the same number for anything that reads headers.
         * Deliberately not the 425 the per-account phone-change cooldown uses: that is a
         * different refusal, and conflating them would tell a client to wait out the wrong
         * one.
         */
        @ExceptionHandler(TwoFactorCooldownException.class)
        public ResponseEntity<ErrorResponse> handleTwoFactorCooldown(TwoFactorCooldownException ex) {
                long remaining = Math.max(ex.getRemainingSeconds(), 0);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .header("Retry-After", String.valueOf(Math.max(remaining, 1)))
                                .body(new ErrorResponse("twofa_cooldown_active", ex.getMessage(), remaining));
        }

        /**
         * A delayed account recovery requested for an account used inside the dormancy period.
         * Same shape as {@code twofa_cooldown_active}: 400, the wait in {@code retryAfterSeconds}
         * and mirrored in {@code Retry-After}.
         */
        @ExceptionHandler(AccountRecoveryCooldownException.class)
        public ResponseEntity<ErrorResponse> handleAccountRecoveryCooldown(AccountRecoveryCooldownException ex) {
                long remaining = Math.max(ex.getRemainingSeconds(), 1);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .header("Retry-After", String.valueOf(remaining))
                                .body(new ErrorResponse("recovery_cooldown_active", ex.getMessage(), remaining));
        }

        /**
         * Completing a recovery that is not ready under the row lock. The fresh state rides along so
         * the client re-renders without another request.
         */
        @ExceptionHandler(AccountRecoveryNotReadyException.class)
        public ResponseEntity<RecoveryErrorResponse> handleAccountRecoveryNotReady(AccountRecoveryNotReadyException ex) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                                .body(new RecoveryErrorResponse("recovery_not_ready", ex.getMessage(), Instant.now(),
                                                ex.getState()));
        }

        @ExceptionHandler(EndpointRetiredException.class)
        public ResponseEntity<ErrorResponse> handleEndpointRetired(EndpointRetiredException ex) {
                return ResponseEntity.status(HttpStatus.GONE)
                                .body(new ErrorResponse("endpoint_retired", ex.getMessage()));
        }

        /**
         * The number typed at a reauthentication step is not the one on the caller's account.
         * One status, one code and one message for every way of being wrong, so the answer
         * cannot be read as "this number belongs to somebody else".
         */
        @ExceptionHandler(ReauthPhoneMismatchException.class)
        public ResponseEntity<ErrorResponse> handleReauthPhoneMismatch(ReauthPhoneMismatchException ex) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(new ErrorResponse("reauth_phone_mismatch", ex.getMessage()));
        }

        @ExceptionHandler(StepUpRequiredException.class)
        public ResponseEntity<ErrorResponse> handleStepUpRequired(StepUpRequiredException ex) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(new ErrorResponse("step_up_required", ex.getMessage()));
        }

        @ExceptionHandler(UnknownUserException.class)
        public ResponseEntity<ErrorResponse> handleUnknownUser(UnknownUserException ex) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(new ErrorResponse("user_not_found", ex.getMessage()));
        }

        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(new ErrorResponse("access_denied", ex.getMessage()));
        }

        @ExceptionHandler(OidcInvalidRequestException.class)
        public ResponseEntity<ErrorResponse> handleOidcInvalidRequest(OidcInvalidRequestException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse(ex.getOauthErrorCode(), ex.getMessage()));
        }

        @ExceptionHandler(LoginFlowException.class)
        public ResponseEntity<ErrorResponse> handleLoginFlow(LoginFlowException ex) {
                return ResponseEntity.status(ex.getStatus())
                                .body(new ErrorResponse(ex.getCode(), ex.getMessage()));
        }

        @ExceptionHandler(GenesisRegistrationException.class)
        public ResponseEntity<ErrorResponse> handleGenesisRegistration(GenesisRegistrationException ex) {
                return ResponseEntity.status(ex.getStatus())
                                .body(new ErrorResponse(ex.getCode(), ex.getMessage()));
        }

        /**
         * An authority transition that was refused for a reason other than malformed bytes. Carries the stable
         * code and, on a backoff or a cooldown, how long to wait.
         */
        @ExceptionHandler(AuthorityTransitionException.class)
        public ResponseEntity<ErrorResponse> handleAuthorityTransition(AuthorityTransitionException ex) {
                ResponseEntity.BodyBuilder builder = ResponseEntity.status(ex.getStatus());
                if (ex.getRetryAfterSeconds() != null) {
                        builder = builder.header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()));
                }
                return builder.body(ex.getRetryAfterSeconds() == null
                                ? new ErrorResponse(ex.getCode(), ex.getMessage())
                                : new ErrorResponse(ex.getCode(), ex.getMessage(), ex.getRetryAfterSeconds()));
        }

        /**
         * A malformed authority record. The decoder's rule name is returned, exactly as for a malformed
         * genesis, so a client implementing the codec can tell which rule refused it; the bytes are never
         * echoed back.
         */
        @ExceptionHandler(InvalidAuthorityRecordException.class)
        public ResponseEntity<ErrorResponse> handleInvalidAuthorityRecord(InvalidAuthorityRecordException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_authority_record",
                                                "Rejected by rule: " + ex.reason()));
        }

        /**
         * A malformed account object. The decoder's rule name is returned so a client implementing the
         * codec can tell which rule refused it; the bytes themselves are never echoed back.
         */
        @ExceptionHandler(InvalidGenesisException.class)
        public ResponseEntity<ErrorResponse> handleInvalidGenesis(InvalidGenesisException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("invalid_genesis", "Rejected by rule: " + ex.reason()));
        }

        @ExceptionHandler(OidcClientAuthenticationException.class)
        public ResponseEntity<ErrorResponse> handleOidcClientAuth(OidcClientAuthenticationException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"oauth2\"")
                                .body(new ErrorResponse("invalid_client", ex.getMessage()));
        }

        /**
         * A request whose body is missing or is not readable as JSON. Without this the
         * catch-all below turns a malformed request into a 500, which blames the server
         * for the caller's mistake and tells the caller nothing.
         */
        @ExceptionHandler(HttpMessageNotReadableException.class)
        public ResponseEntity<ErrorResponse> handleUnreadableBody(HttpMessageNotReadableException ex) {
                log.debug("Unreadable request body", ex);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("malformed_request", "Request body is missing or is not valid JSON."));
        }

        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
                List<String> messages = ex.getBindingResult().getFieldErrors().stream()
                                .map(FieldError::getDefaultMessage)
                                .toList();
                String description = messages.isEmpty() ? "Validation failed" : String.join(", ", messages);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("validation_error", description));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) {
                log.error("Unhandled exception", ex);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(new ErrorResponse("server_error", "Unexpected error"));
        }

        /** An error that carries the account recovery state it was decided on. */
        public record RecoveryErrorResponse(String code, String message, Instant timestamp,
                        AccountRecoveryState recovery) {
        }

        /**
         * {@code retryAfterSeconds} is omitted from the JSON unless a handler sets it, so
         * every existing error body is byte-for-byte what it was.
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public record ErrorResponse(String code, String message, Instant timestamp, Long retryAfterSeconds) {
                public ErrorResponse(String code, String message) {
                        this(code, message, Instant.now(), null);
                }

                public ErrorResponse(String code, String message, long retryAfterSeconds) {
                        this(code, message, Instant.now(), retryAfterSeconds);
                }
        }
}
