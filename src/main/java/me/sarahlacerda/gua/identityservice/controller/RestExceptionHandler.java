package me.sarahlacerda.gua.identityservice.controller;

import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.exception.PinResetCooldownException;
import me.sarahlacerda.gua.identityservice.exception.PinResetNotRequestedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.UnknownUserException;

@RestControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<ErrorResponse> handleInvalidOtp(InvalidOtpException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ErrorResponse("invalid_otp", ex.getMessage()));
    }

    @ExceptionHandler({OtpRateLimitedException.class, RateLimiterException.class})
    public ResponseEntity<ErrorResponse> handleRateLimited(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(new ErrorResponse("rate_limited", ex.getMessage()));
    }

    @ExceptionHandler(PhoneAlreadyLinkedException.class)
    public ResponseEntity<ErrorResponse> handlePhoneAlreadyLinked(PhoneAlreadyLinkedException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(new ErrorResponse("phone_already_linked", ex.getMessage()));
    }

    @ExceptionHandler({InvalidPinException.class, InvalidPinOperationException.class})
    public ResponseEntity<ErrorResponse> handlePinErrors(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ErrorResponse("pin_error", ex.getMessage()));
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
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse("server_error", "Unexpected error"));
    }

    public record ErrorResponse(String code, String message, Instant timestamp) {
        public ErrorResponse(String code, String message) {
            this(code, message, Instant.now());
        }
    }
}
