package me.sarahlacerda.gua.identityservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.OtpVerifyResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.SignupCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.UsernameAvailabilityResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@RestController
@RequestMapping("/signup")
@Validated
@RequiredArgsConstructor
@Tag(name = "Signup", description = "Finalize a new-user signup after OTP verification")
public class SignupController {

    private static final Logger log = LoggerFactory.getLogger(SignupController.class);

    private final IdentityOrchestrationService orchestrationService;

    @GetMapping("/check-username")
    @Operation(summary = "Check whether a username is available", description = "Real-time availability check used by the signup UI. Validates format and reserved-name rules, then queries Matrix for an existing account. Does not consume the signup token or mutate any state.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Availability result returned", content = @Content(schema = @Schema(implementation = UsernameAvailabilityResponse.class))),
            @ApiResponse(responseCode = "400", description = "Username format invalid or reserved", content = @Content)
    })
    public ResponseEntity<UsernameAvailabilityResponse> checkUsernameAvailability(
            @Parameter(description = "Username (localpart) the user is considering", example = "alice", required = true) @RequestParam("username") String username) {
        boolean available = orchestrationService.isUsernameAvailable(username);
        return ResponseEntity.ok(new UsernameAvailabilityResponse(available));
    }

    @PostMapping("/complete")
    @Operation(summary = "Finalize signup with a chosen username and display name", description = "Exchanges a signupToken (issued by /otp/verify for new users) for a Matrix session, provisioning the Matrix account with the user-chosen localpart and display name.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Signup completed; Matrix session issued", content = @Content(schema = @Schema(implementation = OtpVerifyResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid username format or payload", content = @Content),
            @ApiResponse(responseCode = "401", description = "Signup token invalid or expired", content = @Content),
            @ApiResponse(responseCode = "409", description = "Username already taken or phone already linked", content = @Content)
    })
    public ResponseEntity<OtpVerifyResponse> completeSignup(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Signup completion payload with chosen username and display name", required = true, content = @Content(schema = @Schema(implementation = SignupCompleteRequest.class))) @RequestBody @Valid SignupCompleteRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        DeviceMetadata metadata = buildDeviceMetadata(request, servletRequest);
        MatrixSession session = orchestrationService.completeSignup(
                request.getSignupToken(),
                request.getUsername(),
                request.getDisplayName(),
                request.getPin(),
                metadata);
        return ResponseEntity.ok(OtpVerifyResponse.existingUser(
                session.accessToken(), session.userId(), session.deviceId(), session.homeserverBaseUrl()));
    }

    private DeviceMetadata buildDeviceMetadata(SignupCompleteRequest request, HttpServletRequest servletRequest) {
        OtpVerifyRequest.DeviceInfo deviceInfo = request.getDevice();
        if (deviceInfo == null) {
            log.warn(
                    "Signup completion request missing device metadata from {} — device registration & new-device notifications will be skipped",
                    servletRequest.getRemoteAddr());
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
