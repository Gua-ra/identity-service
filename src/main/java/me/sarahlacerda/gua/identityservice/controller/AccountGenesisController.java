package me.sarahlacerda.gua.identityservice.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
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
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.AccountGenesisRegisterRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountGenesisRegisterResponse;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;

/**
 * Registration of an {@code AccountGenesis} the client generated on device (ADM-008 decision 6, step 1).
 *
 * <p>Open by design and self-authenticating: it runs before any OIDC flow exists to authenticate
 * against, and the body carries a possession proof under the key committed inside the genesis itself.
 * Registering creates no account and attaches nothing. The handle it returns is a routing hint, not a
 * capability: a stolen handle attaches nothing, and a planted one fails at the attach proof.
 */
@RestController
@RequestMapping("/account/genesis")
@Validated
@RequiredArgsConstructor
@Tag(name = "Account genesis", description = "Register an on-device AccountGenesis and receive its accountId")
public class AccountGenesisController {

    private final AccountGenesisService accountGenesisService;

    @PostMapping
    @Operation(summary = "Register an AccountGenesis",
            description = "Strictly decodes the canonical bytes, verifies the client's possession proof under the "
                    + "committed authority key, derives the accountId over the bytes as received, and returns a "
                    + "single-use attach handle. Gated by identity.genesis.enabled.",
            security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Genesis registered; accountId and attach handle issued",
                    content = @Content(schema = @Schema(implementation = AccountGenesisRegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Malformed genesis or a proof that does not verify",
                    content = @Content),
            @ApiResponse(responseCode = "403", description = "Issuance under the offered recovery framework is not permitted",
                    content = @Content),
            @ApiResponse(responseCode = "409", description = "This genesis is already attached to an account",
                    content = @Content),
            @ApiResponse(responseCode = "503", description = "Account genesis is not enabled on this deployment",
                    content = @Content)
    })
    public ResponseEntity<AccountGenesisRegisterResponse> register(
            @RequestBody @Valid AccountGenesisRegisterRequest request) {
        AccountGenesisRegisterResponse response =
                accountGenesisService.register(request.getGenesis(), request.getProof());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
