// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller;

import java.time.Clock;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.controller.dto.SecurityNotificationRegisterRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.SecurityNotificationRemoveRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.SecurityNotificationView;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityChallengeService;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityNotificationRegistry;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityNotifications;

/**
 * The security-notification channel every window in ADM-009 depends on (gate 2).
 *
 * <p>Deliberately not a Matrix pusher, and deliberately not this service's existing device-notification seam.
 * A pusher lives under a session, and completing an account recovery ends every session of the user in the
 * same transaction that mints the attacker's PIN, so a pusher would die with the thing the attacker had just
 * destroyed. These registrations are keyed on an installation id the client keeps in the keychain or keystore,
 * and no recovery path can reach them.
 *
 * <p>Bearer-gated, and every endpoint answers 503 while {@code identity.authority.enabled} is false, and 503
 * again while {@code identity.authority.notifications.enabled} is false, so a deployment that has not turned
 * the channel on holds no push destinations at all.
 *
 * <p>There is no OTP here either (ADM-009 decision 9). The registration says nothing about a phone number,
 * and the notification names a label and a time.
 */
@RestController
@RequestMapping("/account/security-notifications")
@Validated
@Tag(name = "Account authority",
        description = "The out-of-band channel a pending authority transition is announced on (ships disabled)")
public class AccountAuthorityNotificationController {

    private final AuthorityNotificationRegistry registry;
    private final AuthorityNotifications notifications;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;
    private final Clock clock;

    public AccountAuthorityNotificationController(AuthorityNotificationRegistry registry,
            AuthorityNotifications notifications, AuthenticatedUserAccessor authenticatedUserAccessor,
            Clock clock) {
        this.registry = registry;
        this.notifications = notifications;
        this.authenticatedUserAccessor = authenticatedUserAccessor;
        this.clock = clock;
    }

    @PostMapping
    @Operation(summary = "Register or refresh this install's security-notification destination",
            description = "An upsert on the installation id, which is client-generated and held in the keychain "
                    + "or keystore so it survives a sign-out. Nothing about this row is removed by a sign-out, a "
                    + "token revocation, a PIN reset, a passkey removal or a completed account recovery, which is "
                    + "the whole property gate 2 asks for. A device authority key may be bound to the row, and "
                    + "only with a signature by that key over a spent challenge. An upsert refreshes a "
                    + "registration; it may not move an existing row's push destination without that signature, "
                    + "because a destination change is a removal and a re-registration wearing one call.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Registered, described without its token",
                    content = @Content(schema = @Schema(implementation = SecurityNotificationView.class))),
            @ApiResponse(responseCode = "400", description = "authority_notification_invalid, "
                    + "authority_notification_invalid_key, authority_notification_invalid_signature or "
                    + "authority_notification_destination_refused",
                    content = @Content),
            @ApiResponse(responseCode = "401", description = "Caller not authenticated", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled or "
                    + "authority_notifications_disabled", content = @Content)
    })
    public ResponseEntity<AuthorityNotificationRegistry.Registered> register(
            @RequestBody @Valid SecurityNotificationRegisterRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        return ResponseEntity.ok(registry.register(userId,
                new AuthorityNotificationRegistry.Registration(request.getInstallationId(), request.getPlatform(),
                        request.getToken(), request.getAppId(), request.getDeviceLabel(),
                        request.getAuthorityDeviceKeyB64(), request.getChallenge(), request.getSignature()),
                sessionHash(servletRequest), clock.instant()));
    }

    @GetMapping
    @Operation(summary = "The live registrations of this account",
            description = "So the account holder can see which of their installs would be warned, and remove one "
                    + "they no longer recognise. The destinations themselves are never returned: each row is named "
                    + "by a fingerprint of its token.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The live registrations"),
            @ApiResponse(responseCode = "503", description = "authority_disabled or "
                    + "authority_notifications_disabled", content = @Content)
    })
    public ResponseEntity<List<SecurityNotificationView>> live() {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        List<SecurityNotificationView> views = registry.listForHolder(userId, clock.instant()).stream()
                .map(row -> new SecurityNotificationView(row.getInstallationId(), row.getPlatform().name(),
                        row.getDeviceLabel(), row.getTokenFingerprint(),
                        row.getAuthorityDeviceKeyB64() != null, row.getLastSeenAt().getEpochSecond()))
                .toList();
        return ResponseEntity.ok(views);
    }

    @PostMapping("/remove")
    @Operation(summary = "Remove one registration, at the price every removal pays",
            description = "A step-up on a factor that is itself past the fresh-factor hold, plus a signature by "
                    + "an active unquarantined device key where the row carries one. That is the price whichever "
                    + "install the request names, including the caller's own: which tier a caller reaches is "
                    + "decided by what they can produce, and a request cannot authenticate itself. From nowhere "
                    + "else: there is no admin path, no bulk delete and nothing reachable from a browser session. "
                    + "Every accepted removal is announced to the remaining registrations, so stripping the "
                    + "channel is loud.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Removed"),
            @ApiResponse(responseCode = "400", description = "authority_notification_invalid, "
                    + "authority_notification_unknown or authority_notification_invalid_signature",
                    content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_factor_too_fresh or "
                    + "authority_recovery_too_recent", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_step_up_required", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled or "
                    + "authority_notifications_disabled", content = @Content)
    })
    public ResponseEntity<Void> remove(@RequestBody @Valid SecurityNotificationRemoveRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        String label = registry.remove(userId,
                new AuthorityNotificationRegistry.Removal(request.getInstallationId(),
                        request.getPasskeyStepUpId(), request.getPasskeyCredential(), request.getPin(),
                        request.getChallenge(), request.getSignature()),
                sessionHash(servletRequest), servletRequest.getRemoteAddr(), clock.instant());
        // Announced here rather than inside the registry, because the notifier reads the registrations and a
        // registry that called it back would be a cycle in the wiring rather than a decision.
        notifications.channelRemoved(userId, label);
        return ResponseEntity.noContent().build();
    }

    /**
     * Binds a challenge to the exact access token that asked for it, exactly as the chain endpoints do.
     *
     * <p>Hashed, so nothing holds the token, and read from the header rather than from anything the caller
     * sends beside it.
     */
    private static String sessionHash(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return AuthorityChallengeService.sessionHash(header == null ? "" : header);
    }
}
