package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Optional payload for starting factor enrollment. The whole body may be omitted, and a client that omits it gets the deployment's own default redirect.")
public class FactorEnrollStartRequest {

    /**
     * Where the enrollment sheet hands back to when the ceremony completes: the app scheme this
     * build of the app answers. Each build answers its own, and the server cannot tell which
     * build is calling, because the bearer token is a homeserver token that names no OIDC
     * client of ours.
     *
     * <p>
     * It is bounded by the deployment's allowlist
     * ({@code idp.login.enroll.redirect-uris}): a value that is not on it is refused with
     * {@code 400 invalid_redirect_uri} rather than honoured. Omit the field to keep the
     * deployment's own resolution.
     */
    @Schema(description = "App-scheme redirect this build answers. Must be one the deployment allows, or the call is refused with invalid_redirect_uri.", example = "global.gua.dev:/oidc")
    private String redirectUri;
}
