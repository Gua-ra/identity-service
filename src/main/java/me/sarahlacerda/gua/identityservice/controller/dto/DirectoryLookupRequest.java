package me.sarahlacerda.gua.identityservice.controller.dto;

import java.util.List;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import io.swagger.v3.oas.annotations.media.Schema;

@Data
@Schema(description = "Address-book phone numbers to match against Gua accounts")
public class DirectoryLookupRequest {

    @NotEmpty
    @Schema(
        description = "Phone numbers in E.164 format. Sent over TLS only; the server digests them "
                + "in memory and never stores or logs the raw numbers. Invalid entries are skipped.",
        example = "[\"+5511999998888\", \"+14165550123\"]")
    private List<String> phones;
}
