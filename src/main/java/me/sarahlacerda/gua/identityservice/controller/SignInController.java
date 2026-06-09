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
import me.sarahlacerda.gua.identityservice.controller.dto.SignInVerifyPinRequest;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.service.IdentityOrchestrationService;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@RestController
@RequestMapping("/signin")
@Validated
@RequiredArgsConstructor
@Tag(name = "Sign-in", description = "Second leg of phone sign-in for users with two-step verification")
public class SignInController {

    private static final Logger log = LoggerFactory.getLogger(SignInController.class);

    private final IdentityOrchestrationService orchestrationService;

    @PostMapping("/verify-pin")
    @Operation(summary = "Complete phone sign-in by verifying the account PIN", description = "Exchanges a short-lived pinChallengeToken (issued by /otp/verify for returning users with two-step verification enabled) plus the user's 6-digit PIN for a Matrix session.", security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "PIN verified; Matrix session issued", content = @Content(schema = @Schema(implementation = OtpVerifyResponse.class))),
            @ApiResponse(responseCode = "400", description = "PIN invalid or malformed payload", content = @Content),
            @ApiResponse(responseCode = "401", description = "PIN challenge invalid or expired", content = @Content),
            @ApiResponse(responseCode = "429", description = "PIN locked due to repeated failures", content = @Content)
    })
    public ResponseEntity<OtpVerifyResponse> verifyPin(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "PIN-challenge token plus the user's 6-digit PIN and optional device metadata", required = true, content = @Content(schema = @Schema(implementation = SignInVerifyPinRequest.class))) @RequestBody @Valid SignInVerifyPinRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        DeviceMetadata metadata = buildDeviceMetadata(request, servletRequest);
        MatrixSession session = orchestrationService.verifySignInPin(
                request.getPinChallengeToken(),
                request.getPin(),
                metadata);
        return ResponseEntity.ok(OtpVerifyResponse.existingUser(
                session.accessToken(), session.userId(), session.deviceId(), session.homeserverBaseUrl()));
    }

    private DeviceMetadata buildDeviceMetadata(SignInVerifyPinRequest request, HttpServletRequest servletRequest) {
        OtpVerifyRequest.DeviceInfo deviceInfo = request.getDevice();
        if (deviceInfo == null) {
            log.warn(
                    "/signin/verify-pin request missing device metadata from {} — device registration & new-device notifications will be skipped",
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
