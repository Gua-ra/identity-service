package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "OTP verification payload used to create or resume a Matrix session")
public class OtpVerifyRequest {

    @NotBlank
    @Schema(description = "Phone number that received the OTP", example = "+12025550123")
    private String phone;

    @NotBlank
    @Schema(description = "One-time password that was delivered to the phone", example = "123456")
    private String code;

    @Schema(description = "Optional display name to apply to the Matrix user", example = "Sarah L.")
    private String displayName;

    @Schema(description = "Optional security PIN required for returning users", example = "654321")
    private String pin;

    @Valid
    @Schema(description = "Metadata about the device requesting the session")
    private DeviceInfo device;

    @Getter
    @Setter
    @Schema(description = "Client device details used for trust decisions")
    public static class DeviceInfo {
        @Schema(description = "Human readable name the client reports", example = "Sarah's iPhone")
        private String name;

        @Schema(description = "Platform or OS of the device", example = "iOS")
        private String platform;

        @Schema(description = "Client application version", example = "1.2.3")
        private String appVersion;
    }
}
