package me.sarahlacerda.gua.identityservice.controller;

import java.util.List;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.DirectoryLookupRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.DirectoryLookupResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.UsernameResolutionResponse;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.service.ContactDiscoveryService;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;

@RestController
@RequestMapping("/directory")
@Validated
@RequiredArgsConstructor
@Tag(name = "Directory", description = "Privacy-preserving contact discovery")
public class DirectoryController {

    private final DirectoryService directoryService;
    private final ContactDiscoveryService contactDiscoveryService;
    private final HomeserverRegistry homeserverRegistry;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;

    @PostMapping("/lookup")
    @Operation(
        summary = "Match address-book phones to Gua accounts",
        description = "Accepts E.164 phone numbers over TLS, digests them in memory with the server-side "
                + "peppered HMAC and returns the contacts that are on Gua and discoverable. Raw numbers are "
                + "never stored or logged.",
        security = @SecurityRequirement(name = "oidcAccessToken")
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Matches returned", content = @Content(schema = @Schema(implementation = DirectoryLookupResponse.class))),
        @ApiResponse(responseCode = "400", description = "Validation failed or batch too large", content = @Content),
        @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many lookup attempts", content = @Content)
    })
    public ResponseEntity<DirectoryLookupResponse> lookup(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Address-book phone numbers (E.164) to match",
            required = true,
            content = @Content(schema = @Schema(implementation = DirectoryLookupRequest.class))
        )
        @RequestBody @Valid DirectoryLookupRequest request
    ) {
        authenticatedUserAccessor.requireCurrentUserId();
        List<DirectoryLookupResponse.ContactMatchView> matches = contactDiscoveryService.match(request.getPhones())
            .stream()
            .map(match -> new DirectoryLookupResponse.ContactMatchView(
                match.phoneNumber(), match.userId(), match.username(), match.displayName()))
            .toList();
        return ResponseEntity.ok(new DirectoryLookupResponse(matches));
    }

    @GetMapping("/resolve")
    @Operation(
        summary = "Resolve a global username",
        description = "Resolves a global Gua username to the account's Matrix user id and the homeserver it lives on. This is the routing lookup that lets the federation locate where an identity is hosted.",
        security = @SecurityRequirement(name = "oidcAccessToken")
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Username resolved", content = @Content(schema = @Schema(implementation = UsernameResolutionResponse.class))),
        @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
        @ApiResponse(responseCode = "404", description = "Username not found", content = @Content)
    })
    public ResponseEntity<UsernameResolutionResponse> resolveUsername(@RequestParam("username") String username) {
        authenticatedUserAccessor.requireCurrentUserId();
        return directoryService.resolveByUsername(username)
            .map(entry -> ResponseEntity.ok(new UsernameResolutionResponse(
                entry.getUsername(),
                entry.getUserId(),
                resolveHomeserverDomain(entry),
                entry.getDisplayName())))
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Maps the stored homeserver id to its Matrix domain. Falls back to the domain
     * embedded in the MXID for legacy rows that predate routing.
     */
    private String resolveHomeserverDomain(DirectoryEntry entry) {
        if (entry.getHomeserverId() != null) {
            return homeserverRegistry.findById(entry.getHomeserverId())
                .map(hs -> hs.domain())
                .orElse(domainFromUserId(entry.getUserId()));
        }
        return domainFromUserId(entry.getUserId());
    }

    private String domainFromUserId(String userId) {
        int colon = userId.indexOf(':');
        return colon >= 0 ? userId.substring(colon + 1) : null;
    }
}
