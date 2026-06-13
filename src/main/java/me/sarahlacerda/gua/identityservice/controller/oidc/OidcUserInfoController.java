package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.Optional;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@RestController
@RequiredArgsConstructor
@Tag(name = "OIDC UserInfo", description = "OpenID Connect user profile endpoint")
public class OidcUserInfoController {

    private final OidcTokenService tokenService;
    private final DirectoryService directoryService;

    @GetMapping("/userinfo")
    @Operation(summary = "Retrieve the authenticated user's profile", description = "Returns the subject identifier, phone number, and display name associated with a validated access token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile", content = @Content(schema = @Schema(implementation = UserInfoResponse.class))),
            @ApiResponse(responseCode = "401", description = "Missing or invalid access token", content = @Content)
    })
    public ResponseEntity<UserInfoResponse> userInfo(
            @Parameter(description = "Bearer access token issued by the token endpoint.", required = true, example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...") @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String token = authorization.substring("Bearer ".length());
        Optional<OidcAuthenticatedPrincipal> principal = tokenService.parseAccessToken(token);
        if (principal.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        OidcAuthenticatedPrincipal user = principal.get();
        String maskedPhone = directoryService.findMaskedPhoneByUserId(user.userId()).orElse(null);
        return ResponseEntity.ok(new UserInfoResponse(
                user.userId(),
                user.phoneNumber(),
                maskedPhone,
                user.displayName(),
                user.preferredUsername()));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UserInfoResponse(
            String sub,
            @JsonProperty("phone_number") String phoneNumber,
            @JsonProperty("phone_number_masked") String phoneNumberMasked,
            String name,
            @JsonProperty("preferred_username") String preferredUsername) {
    }
}
