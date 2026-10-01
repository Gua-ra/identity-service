// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Start an approval a browser session cannot grant itself")
public class AuthorityApprovalStartRequest {

    @NotBlank
    @Schema(description = "Opaque action id, which the device describes to the reader and whose digest it "
            + "signs over", requiredMode = Schema.RequiredMode.REQUIRED)
    private String action;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}
