package me.sarahlacerda.gua.identityservice.controller;

import java.util.List;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;

@RestController
@RequestMapping("/directory")
@Validated
@RequiredArgsConstructor
@Tag(name = "Directory", description = "Privacy-preserving contact discovery")
public class DirectoryController {

    private final DirectoryService directoryService;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;

    @PostMapping("/lookup")
    @Operation(
        summary = "Resolve contact digests",
        description = "Accepts a list of HMAC digests of phone numbers generated on the client and returns the contacts that are already using Gua. Used for contact discovery",
        security = @SecurityRequirement(name = "matrixToken")
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Matches returned", content = @Content(schema = @Schema(implementation = DirectoryLookupResponse.class))),
        @ApiResponse(responseCode = "400", description = "Validation failed", content = @Content),
        @ApiResponse(responseCode = "401", description = "Authentication required", content = @Content),
        @ApiResponse(responseCode = "429", description = "Too many lookup attempts", content = @Content)
    })
    public ResponseEntity<DirectoryLookupResponse> lookup(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User identifier and collection of hashed phone digests to resolve",
            required = true,
            content = @Content(schema = @Schema(implementation = DirectoryLookupRequest.class))
        )
        @RequestBody @Valid DirectoryLookupRequest request
    ) {
        authenticatedUserAccessor.requireUserIdMatches(request.getUserId());
        List<DirectoryLookupResponse.DirectoryMatchView> matches = directoryService.lookupMatches(request.getDigests())
            .stream()
            .map(match -> new DirectoryLookupResponse.DirectoryMatchView(match.digest(), match.userId(), match.displayName()))
            .toList();
        return ResponseEntity.ok(new DirectoryLookupResponse(matches));
    }
}
