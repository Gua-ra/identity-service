package me.sarahlacerda.gua.identityservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import org.springframework.http.ResponseEntity;
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
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.OtpChangeNumberRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpSendRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyResponse;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@RestController
@RequestMapping("/otp")
@Validated
@RequiredArgsConstructor
@Tag(name = "OTP", description = "Phone-based authentication and verification flows")
public class OtpController {

    private final IdentityOrchestrationService orchestrationService;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;

    @PostMapping("/send")
    @Operation(
        summary = "Send an OTP to a user's phone",
        description = "Creates a one-time password for the supplied phone number, applies rate limits, and dispatches the SMS using the client's preferred language when provided.",
        security = {}
    )
    @ApiResponses({
        @ApiResponse(responseCode = "202", description = "OTP accepted and dispatched"),
        @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
        @ApiResponse(responseCode = "429", description = "Rate limit exceeded", content = @Content)
    })
    public ResponseEntity<Void> sendOtp(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Phone number to receive the OTP and optional language preference",
            required = true,
            content = @Content(schema = @Schema(implementation = OtpSendRequest.class))
        )
        @RequestBody @Valid OtpSendRequest request,
        @Parameter(hidden = true) HttpServletRequest servletRequest
    ) {
        orchestrationService.sendOtp(request.getPhone(), servletRequest.getRemoteAddr(), request.getLanguage());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/verify")
    @Operation(
        summary = "Verify an OTP and establish a Matrix session",
        description = "Validates the submitted OTP, provisions or looks up the Matrix account, enforces optional PIN checks, and returns the Matrix access token details.",
        security = {}
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "OTP verified; session issued", content = @Content(schema = @Schema(implementation = OtpVerifyResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid request payload", content = @Content),
        @ApiResponse(responseCode = "401", description = "OTP invalid or expired", content = @Content),
        @ApiResponse(responseCode = "403", description = "PIN validation failed", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many verification attempts", content = @Content)
    })
    public ResponseEntity<OtpVerifyResponse> verifyOtp(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "OTP verification payload including the code, optional display name, PIN, and device metadata",
            required = true,
            content = @Content(schema = @Schema(implementation = OtpVerifyRequest.class))
        )
        @RequestBody @Valid OtpVerifyRequest request,
        @Parameter(hidden = true) HttpServletRequest servletRequest
    ) {
        DeviceMetadata metadata = buildDeviceMetadata(request, servletRequest);
        MatrixSession session = orchestrationService.verifyOtpAndSignIn(
            request.getPhone(),
            request.getCode(),
            request.getDisplayName(),
            request.getPin(),
            metadata
        );
        OtpVerifyResponse response = new OtpVerifyResponse(session.accessToken(), session.userId(), session.deviceId(), session.homeserverBaseUrl());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-number")
    @Operation(
        summary = "Change the verified phone number of an existing user",
        description = "After validating the caller's authentication token, verifies the new phone number via OTP and binds it to the Matrix account while preserving existing directory data.",
        security = @SecurityRequirement(name = "matrixToken")
    )
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Phone number updated"),
        @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
        @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
        @ApiResponse(responseCode = "403", description = "PIN invalid", content = @Content),
        @ApiResponse(responseCode = "409", description = "Phone already linked to another user", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many change-number attempts", content = @Content)
    })
    public ResponseEntity<Void> changeNumber(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "OTP and PIN payload for re-binding a user's phone number",
            required = true,
            content = @Content(schema = @Schema(implementation = OtpChangeNumberRequest.class))
        )
        @RequestBody @Valid OtpChangeNumberRequest request
    ) {
        authenticatedUserAccessor.requireUserIdMatches(request.getUserId());
        orchestrationService.changePhoneNumber(request.getUserId(), request.getNewPhone(), request.getCode(), request.getPin());
        return ResponseEntity.noContent().build();
    }

    private DeviceMetadata buildDeviceMetadata(OtpVerifyRequest request, HttpServletRequest servletRequest) {
        OtpVerifyRequest.DeviceInfo deviceInfo = request.getDevice();
        if (deviceInfo == null) {
            return null;
        }
        return DeviceMetadata.builder()
            .deviceName(deviceInfo.getName())
            .platform(deviceInfo.getPlatform())
            .appVersion(deviceInfo.getAppVersion())
            .ipAddress(servletRequest.getRemoteAddr())
            .build();
    }
}
