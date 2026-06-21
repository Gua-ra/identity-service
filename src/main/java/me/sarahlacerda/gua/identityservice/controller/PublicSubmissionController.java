package me.sarahlacerda.gua.identityservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.BetaSignupRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PublicSubmissionResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.SupportRequest;
import me.sarahlacerda.gua.identityservice.service.PublicSubmissionService;

/**
 * Public, unauthenticated endpoints behind the gua.global support / beta-access
 * web forms. Submissions are persisted and the operator is notified out-of-band
 * via a GitHub issue. Protected by Bean Validation, a hidden honeypot field, and
 * the shared per-IP rate limiter (see application.yml rate-limits).
 */
@RestController
@RequestMapping("/public")
@Validated
@RequiredArgsConstructor
@Tag(name = "Public", description = "Unauthenticated gua.global web-form submissions")
public class PublicSubmissionController {

    private static final Logger log = LoggerFactory.getLogger(PublicSubmissionController.class);

    private final PublicSubmissionService publicSubmissionService;

    @PostMapping("/support")
    @Operation(summary = "Submit a support request", description = "Accepts a support request from the public gua.global support form. Persists it and opens a GitHub inbox issue for the operator. Honeypot-protected and rate limited.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Submission accepted", content = @Content(schema = @Schema(implementation = PublicSubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many submissions", content = @Content)
    })
    public ResponseEntity<PublicSubmissionResponse> submitSupport(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Support request payload", required = true, content = @Content(schema = @Schema(implementation = SupportRequest.class))) @RequestBody @Valid SupportRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        if (isHoneypotTripped(request.getWebsite())) {
            // Silently accept so a bot gets no signal that it was filtered.
            log.info("Dropped honeypot-tripped support submission from {}", servletRequest.getRemoteAddr());
            return ResponseEntity.ok(PublicSubmissionResponse.ok());
        }
        publicSubmissionService.recordSupport(
                request.getName(), request.getEmail(), request.getMessage(), servletRequest.getRemoteAddr());
        return ResponseEntity.ok(PublicSubmissionResponse.ok());
    }

    @PostMapping("/beta-signup")
    @Operation(summary = "Sign up for beta access", description = "Accepts a beta-access sign-up from the public gua.global form. Persists it and opens a GitHub inbox issue for the operator. Honeypot-protected and rate limited.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Submission accepted", content = @Content(schema = @Schema(implementation = PublicSubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many submissions", content = @Content)
    })
    public ResponseEntity<PublicSubmissionResponse> submitBetaSignup(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Beta sign-up payload", required = true, content = @Content(schema = @Schema(implementation = BetaSignupRequest.class))) @RequestBody @Valid BetaSignupRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        if (isHoneypotTripped(request.getWebsite())) {
            log.info("Dropped honeypot-tripped beta submission from {}", servletRequest.getRemoteAddr());
            return ResponseEntity.ok(PublicSubmissionResponse.ok());
        }
        publicSubmissionService.recordBetaSignup(
                request.getEmail(), request.getPlatform(), servletRequest.getRemoteAddr());
        return ResponseEntity.ok(PublicSubmissionResponse.ok());
    }

    private boolean isHoneypotTripped(String honeypot) {
        return StringUtils.hasText(honeypot);
    }
}
