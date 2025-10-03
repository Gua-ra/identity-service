package me.sarahlacerda.gua.identityservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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

import me.sarahlacerda.gua.identityservice.controller.dto.PinResetCompleteRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinResetRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.PinUpdateRequest;
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

    @PostMapping("/pin")
    @Operation(
        summary = "Set or update the account PIN",
        description = "Sets an initial security PIN or updates an existing one when the current PIN is provided.",
        security = @SecurityRequirement(name = "matrixToken")
    )
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "PIN stored"),
        @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
        @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
        @ApiResponse(responseCode = "403", description = "Current PIN invalid", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many PIN updates", content = @Content)
    })
    public ResponseEntity<Void> setOrUpdatePin(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Payload containing the user identifier, new PIN, and optional current PIN",
            required = true,
            content = @Content(schema = @Schema(implementation = PinUpdateRequest.class))
        )
        @RequestBody @Valid PinUpdateRequest request
    ) {
        authenticatedUserAccessor.requireUserIdMatches(request.getUserId());
        if (request.getCurrentPin() == null || request.getCurrentPin().isBlank()) {
            userSecurityService.setInitialPin(request.getUserId(), request.getNewPin());
        } else {
            userSecurityService.updatePin(request.getUserId(), request.getCurrentPin(), request.getNewPin());
        }
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/pin/reset")
    @Operation(
        summary = "Request a PIN reset",
        description = "Initiates the PIN recovery flow by sending an OTP to the verified phone number.",
        security = {}
    )
    @ApiResponses({
        @ApiResponse(responseCode = "202", description = "Reset initiated"),
        @ApiResponse(responseCode = "400", description = "Validation or cooldown failure", content = @Content),
        @ApiResponse(responseCode = "404", description = "User or phone not found", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many reset requests", content = @Content)
    })
    public ResponseEntity<Void> requestPinReset(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User identifier and verified phone number to receive the OTP",
            required = true,
            content = @Content(schema = @Schema(implementation = PinResetRequest.class))
        )
        @RequestBody @Valid PinResetRequest request,
        @Parameter(hidden = true) HttpServletRequest servletRequest
    ) {
        userSecurityService.requestPinReset(request.getUserId(), request.getPhone(), servletRequest.getRemoteAddr());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/pin/reset/complete")
    @Operation(
        summary = "Complete a PIN reset",
        description = "Verifies the OTP sent during the reset request and applies the new PIN.",
        security = {}
    )
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "PIN reset successful"),
        @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
        @ApiResponse(responseCode = "401", description = "OTP invalid or expired", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many reset attempts", content = @Content)
    })
    public ResponseEntity<Void> completePinReset(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "OTP and new PIN payload to finalize recovery",
            required = true,
            content = @Content(schema = @Schema(implementation = PinResetCompleteRequest.class))
        )
        @RequestBody @Valid PinResetCompleteRequest request
    ) {
        userSecurityService.completePinReset(request.getUserId(), request.getPhone(), request.getCode(), request.getNewPin());
        return ResponseEntity.noContent().build();
    }
}
