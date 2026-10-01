package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Optional payload for starting factor enrollment. The whole body may be omitted, and a client that omits it gets the deployment's own default redirect.")
public class FactorEnrollStartRequest {

    @Schema(description = "App-scheme redirect this build answers. Must be one the deployment allows, or the call is refused with invalid_redirect_uri.", example = "global.gua.dev:/oidc")
    private String redirectUri;
}
