package me.sarahlacerda.gua.identityservice.controller.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinChangeStartResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinStatusResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.PinUpdateRequest;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

@RestController
@RequestMapping("/security")
@Validated
@RequiredArgsConstructor
@Tag(name = "Security", description = "PIN management and recovery flows")
public class SecurityController {

    private final UserSecurityService userSecurityService;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;
    private final IdentityServiceProperties properties;

    @GetMapping("/pin/status")
    @Operation(summary = "Check whether the authenticated user has a PIN set", description = "Returns hasPin=true once the user has configured a security PIN. Used by clients to drive the 'set up two-step verification' nudge.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "PIN status"),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
    })
    public ResponseEntity<PinStatusResponse> pinStatus() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        return ResponseEntity.ok(new PinStatusResponse(userSecurityService.hasPin(userId)));
    }

    @PostMapping("/pin")
    @Operation(summary = "Set the initial account PIN", description = "Stores the user's first security PIN. Updating an existing PIN must use /security/pin/change/start + /complete (OTP-protected).", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN stored"),
            @ApiResponse(responseCode = "400", description = "Validation failed or PIN already set (use change flow)", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content)
    })
    public ResponseEntity<Void> setInitialPin(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Payload containing the user identifier and the new PIN", required = true, content = @Content(schema = @Schema(implementation = PinUpdateRequest.class))) @RequestBody @Valid PinUpdateRequest request) {
        authenticatedUserAccessor.requireUserIdMatches(request.getUserId());
        if (request.getCurrentPin() != null && !request.getCurrentPin().isBlank()) {
            throw new InvalidPinOperationException("Use /security/pin/change/start to change an existing PIN");
        }
        userSecurityService.setInitialPin(request.getUserId(), request.getNewPin());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/pin/change/start")
    @Operation(summary = "Start an OTP-protected PIN change", description = "Verifies the current PIN, enforces the change cooldown, and sends an OTP to the verified phone. Returns a challenge to redeem at /security/pin/change/complete.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Challenge created and OTP sent"),
            @ApiResponse(responseCode = "400", description = "Validation failed or current PIN incorrect", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
            @ApiResponse(responseCode = "425", description = "Cooldown between PIN changes still active", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many attempts (PIN locked or rate limited)", content = @Content)
    })
    public ResponseEntity<PinChangeStartResponse> startPinChange(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Current PIN and phone to receive the OTP", required = true, content = @Content(schema = @Schema(implementation = PinChangeStartRequest.class))) @RequestBody @Valid PinChangeStartRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String challengeId = userSecurityService.startPinChange(userId, request.getPhone(), request.getCurrentPin(),
                servletRequest.getRemoteAddr());
        long ttlSeconds = properties.getSecurity().getPinChangeChallengeTtl().toSeconds();
        return ResponseEntity.ok(new PinChangeStartResponse(challengeId, ttlSeconds));
    }

    @PostMapping("/pin/change/complete")
    @Operation(summary = "Complete an OTP-protected PIN change", description = "Redeems a challenge from /security/pin/change/start together with the OTP delivered by SMS and the new PIN.", security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN changed"),
            @ApiResponse(responseCode = "400", description = "Validation failed or OTP invalid", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication required or challenge missing/expired", content = @Content),
            @ApiResponse(responseCode = "425", description = "Cooldown between PIN changes still active", content = @Content)
    })
    public ResponseEntity<Void> completePinChange(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Challenge identifier, OTP, and new PIN", required = true, content = @Content(schema = @Schema(implementation = PinChangeCompleteRequest.class))) @RequestBody @Valid PinChangeCompleteRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        userSecurityService.completePinChange(userId, request.getChallengeId(), request.getOtpCode(),
                request.getNewPin());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/pin/reset")
    @Operation(summary = "Request a PIN reset", description = "Initiates the PIN recovery flow by sending an OTP to the verified phone number.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Reset initiated"),
            @ApiResponse(responseCode = "400", description = "Validation or cooldown failure", content = @Content),
            @ApiResponse(responseCode = "404", description = "User or phone not found", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many reset requests", content = @Content)
    })
    public ResponseEntity<Void> requestPinReset(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "User identifier and verified phone number to receive the OTP", required = true, content = @Content(schema = @Schema(implementation = PinResetRequest.class))) @RequestBody @Valid PinResetRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        userSecurityService.requestPinReset(request.getUserId(), request.getPhone(), servletRequest.getRemoteAddr());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/pin/reset/complete")
    @Operation(summary = "Complete a PIN reset", description = "Verifies the OTP sent during the reset request and applies the new PIN.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "PIN reset successful"),
            @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
            @ApiResponse(responseCode = "401", description = "OTP invalid or expired", content = @Content),
            @ApiResponse(responseCode = "429", description = "Too many reset attempts", content = @Content)
    })
    public ResponseEntity<Void> completePinReset(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "OTP and new PIN payload to finalize recovery", required = true, content = @Content(schema = @Schema(implementation = PinResetCompleteRequest.class))) @RequestBody @Valid PinResetCompleteRequest request) {
        userSecurityService.completePinReset(request.getUserId(), request.getPhone(), request.getCode(),
                request.getNewPin());
        return ResponseEntity.noContent().build();
    }
}
