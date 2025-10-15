package me.sarahlacerda.gua.identityservice.controller;

import java.util.Optional;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@RestController
@RequiredArgsConstructor
public class OidcUserInfoController {

    private final OidcTokenService tokenService;

    @GetMapping("/userinfo")
    public ResponseEntity<UserInfoResponse> userInfo(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization
    ) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String token = authorization.substring("Bearer ".length());
        Optional<OidcAuthenticatedPrincipal> principal = tokenService.parseAccessToken(token);
        if (principal.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        OidcAuthenticatedPrincipal user = principal.get();
        return ResponseEntity.ok(new UserInfoResponse(user.userId(), user.phoneNumber(), user.displayName()));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record UserInfoResponse(
        String sub,
        @JsonProperty("phone_number") String phoneNumber,
        String name
    ) {}
}
