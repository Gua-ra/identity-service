package me.sarahlacerda.gua.identityservice.controller;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeChallengeNotFoundException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinResetNotRequestedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.SmsRegionNotSupportedException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;
import me.sarahlacerda.gua.identityservice.exception.UsernameTakenException;
import me.sarahlacerda.gua.identityservice.exception.WeakPinException;

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

        @ExceptionHandler(SmsRegionNotSupportedException.class)
        public ResponseEntity<ErrorResponse> handleSmsRegionNotSupported(SmsRegionNotSupportedException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("phone_region_unsupported", ex.getMessage()));
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

        @ExceptionHandler(PinResetCooldownException.class)
        public ResponseEntity<ErrorResponse> handlePinResetCooldown(PinResetCooldownException ex) {
                String message = ex.getRemainingSeconds() > 0
                                ? ex.getMessage() + " (retry in " + ex.getRemainingSeconds() + "s)"
                                : ex.getMessage();
                return ResponseEntity.status(HttpStatus.TOO_EARLY)
                                .body(new ErrorResponse("pin_reset_cooldown", message));
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

        @ExceptionHandler(PinResetNotRequestedException.class)
        public ResponseEntity<ErrorResponse> handlePinResetNotRequested(PinResetNotRequestedException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ErrorResponse("pin_reset_not_requested", ex.getMessage()));
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

        @ExceptionHandler(OidcClientAuthenticationException.class)
        public ResponseEntity<ErrorResponse> handleOidcClientAuth(OidcClientAuthenticationException ex) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .header("WWW-Authenticate", "Basic realm=\"oauth2\"")
                                .body(new ErrorResponse("invalid_client", ex.getMessage()));
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

        public record ErrorResponse(String code, String message, Instant timestamp) {
                public ErrorResponse(String code, String message) {
                        this(code, message, Instant.now());
                }
        }
}
