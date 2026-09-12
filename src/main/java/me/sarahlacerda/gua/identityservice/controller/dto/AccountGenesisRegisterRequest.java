package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Registration of an {@code AccountGenesis} the client generated on device (ADM-008 decision 3).
 *
 * <p>Both fields are base64url without padding. The proof is not part of the genesis: it shows that
 * whoever is registering these bytes holds the authority key committed inside them.
 */
@Getter
@Setter
@Schema(description = "An AccountGenesis and the client's proof that it holds the committed authority key")
public class AccountGenesisRegisterRequest {

    @NotBlank
    @Schema(description = "Canonical AccountGenesis bytes (87 bytes), base64url without padding", requiredMode = Schema.RequiredMode.REQUIRED)
    private String genesis;

    @NotBlank
    @Schema(description = "Ed25519 signature by the authority key over the ASCII domain "
            + "\"gua-account-genesis-proof.v1\" followed by the canonical bytes, base64url without padding",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String proof;
}
