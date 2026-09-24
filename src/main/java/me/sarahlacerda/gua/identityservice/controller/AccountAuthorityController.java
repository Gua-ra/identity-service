// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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

import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityApprovalResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityApprovalSignRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityApprovalStartRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityApprovalView;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityCandidateRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityChallengeRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityChallengeResponse;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityOpposeRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthorityRecordSubmission;
import me.sarahlacerda.gua.identityservice.controller.dto.AuthoritySubmissionResponse;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.service.authority.AccountAuthorityService;
import me.sarahlacerda.gua.identityservice.service.authority.AccountAuthorityService.Submitted;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityApprovalService;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityChallengeService;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy;

/**
 * The account authority chain: adoption, the device lifecycle, and the approval a browser session cannot
 * grant itself (ADM-009).
 *
 * <p>Every endpoint is bearer-gated and every one of them answers 503 {@code authority_disabled} while
 * {@code identity.authority.enabled} is false, which is how the whole feature ships. Nothing here is reachable
 * from the login flow, from an enrollment session, or from any path that existed before it.
 *
 * <p>Four of them additionally require a native session, because the authority key lives in the platform
 * keychain or keystore and the browser holds no authority, ever (ADM-009 decision 6). The approval pair is the
 * one place a web session appears, and there it starts an object an authority device must sign.
 *
 * <p><b>There is no OTP anywhere in this controller</b>, in any combination, at any step (ADM-009 decision 9).
 * A guard test fails the build if it ever references the OTP services.
 */
@RestController
@RequestMapping("/account/authority")
@Validated
@Tag(name = "Account authority",
        description = "The account authority chain, adoption and the device lifecycle (ships disabled)")
public class AccountAuthorityController {

    private final AccountAuthorityService authorityService;
    private final AuthorityApprovalService approvalService;
    private final AuthorityAccounts accounts;
    private final AuthorityPolicy policy;
    private final AuthenticatedUserAccessor authenticatedUserAccessor;
    private final java.time.Clock clock;

    public AccountAuthorityController(AccountAuthorityService authorityService,
            AuthorityApprovalService approvalService, AuthorityAccounts accounts, AuthorityPolicy policy,
            AuthenticatedUserAccessor authenticatedUserAccessor, java.time.Clock clock) {
        this.authorityService = authorityService;
        this.approvalService = approvalService;
        this.accounts = accounts;
        this.policy = policy;
        this.authenticatedUserAccessor = authenticatedUserAccessor;
        this.clock = clock;
    }

    @PostMapping("/challenge")
    @Operation(summary = "Mint the challenge one authority transition will sign",
            description = "Accepts the step-up this purpose is scoped to and mints 32 CSPRNG bytes held against "
                    + "this account and this session, single use, burned on acceptance and on refusal, expiring "
                    + "in at most 15 minutes. The step-up and the challenge are minted together so the step-up "
                    + "can never be older than the challenge it authorizes. A step-up taken for a phone change "
                    + "or a PIN change does not carry over, and no code sent to the account's number is "
                    + "accepted here at any step.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Challenge minted",
                    content = @Content(schema = @Schema(implementation = AuthorityChallengeResponse.class))),
            @ApiResponse(responseCode = "401", description = "Caller not authenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_native_session_required, "
                    + "authority_factor_too_fresh or authority_recovery_too_recent", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_step_up_required: no accepted factor was "
                    + "produced", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthorityChallengeResponse> challenge(@RequestBody @Valid AuthorityChallengeRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        AuthorityChallengeService.Minted minted = authorityService.challenge(userId,
                authenticatedUserAccessor.currentClientId(), sessionHash(servletRequest), request.getPurpose(),
                request.getPasskeyStepUpId(), request.getPasskeyCredential(), request.getPin(),
                servletRequest.getRemoteAddr());
        return ResponseEntity.ok(new AuthorityChallengeResponse(minted.challenge(),
                secondsUntil(minted.expiresAt())));
    }

    @PostMapping("/adopt")
    @Operation(summary = "Root a bootstrap account",
            description = "Records a pending AdoptRoot at seq 1 and starts the opposition window. Refused on a "
                    + "non-empty chain and on a class 0x01 account, refused without the confirmation that the "
                    + "recovery key was stored, and refused unless the session is the native app. The account's "
                    + "permanent id does not change and the genesis row is untouched: adoption gives a class "
                    + "0x00 account authority its id does not commit.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending, with its window",
                    content = @Content(schema = @Schema(implementation = AuthoritySubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "invalid_authority_record, with the rule that "
                    + "refused it", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_artifact_unconfirmed, "
                    + "authority_native_session_required, authority_adoption_not_permitted, "
                    + "authority_challenge_invalid, authority_factor_too_fresh or authority_recovery_too_recent",
                    content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_position_refused, "
                    + "authority_pending_conflict, authority_head_conflict or authority_account_mismatch",
                    content = @Content),
            @ApiResponse(responseCode = "429", description = "authority_backoff or authority_cooldown",
                    content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthoritySubmissionResponse> adopt(@RequestBody @Valid AuthorityRecordSubmission request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        Submitted submitted = authorityService.adopt(userId, authenticatedUserAccessor.currentClientId(),
                sessionHash(servletRequest), request.getRecord(), request.getSignature(), request.getChallenge(),
                request.isRecoveryArtifactConfirmed());
        return accepted(submitted);
    }

    @PostMapping("/oppose")
    @Operation(summary = "Object to the pending transition",
            description = "Cancels every pending adoption on the account, not only the one named. Needs no factor "
                    + "beyond the session the first time, because at seq 1 the account holds no authority to "
                    + "weigh; the second and later oppositions need a step-up on any factor at any age. "
                    + "Objecting to a grant or to a device revocation has to come from a device that holds this "
                    + "account's authority and is refused here.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Cancelled, or nothing was pending"),
            @ApiResponse(responseCode = "403", description = "authority_opposition_device_required or "
                    + "authority_opposition_refused", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_step_up_required", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<Void> oppose(@RequestBody(required = false) AuthorityOpposeRequest request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        AuthorityOpposeRequest body = request == null ? new AuthorityOpposeRequest() : request;
        authorityService.oppose(userId, body.getRecordHash(), body.getPasskeyStepUpId(),
                body.getPasskeyCredential(), body.getPin(), servletRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/oppose/record")
    @Operation(summary = "Object to the pending transition with a signed record",
            description = "The Oppose record of ADM-009 decision 2, signed by a key the chain has active and "
                    + "unquarantined right now. It takes no slot and starts no window: it cancels the record "
                    + "it names, or it is refused. This is what decisions 5 and 7 mean by an active device "
                    + "objecting, and it is the claim a bearer session cannot make, because a stolen session "
                    + "would otherwise veto the owner's own revocation of the thief's device. No factor is "
                    + "asked for and no hold is weighed: the holds gate starting a transition, never opposing "
                    + "one.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Cancelled, extended, or nothing was pending"),
            @ApiResponse(responseCode = "400", description = "invalid_authority_record", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_signer_refused, "
                    + "authority_device_quarantined, authority_opposition_refused or "
                    + "authority_challenge_invalid", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_opposition_stale, "
                    + "authority_extension_spent: this window has already been postponed once, or "
                    + "authority_account_mismatch", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<Void> opposeWithRecord(@RequestBody @Valid AuthorityRecordSubmission request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        authorityService.opposeWithRecord(userId, authenticatedUserAccessor.currentClientId(),
                sessionHash(servletRequest), request.getRecord(), request.getSignature(), request.getChallenge());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/device/candidate")
    @Operation(summary = "Offer this device's own public key for a grant",
            description = "The new device posts only its public key, under its own session, and gets back a "
                    + "short fingerprint. The granting device reads the account's candidates, shows the same "
                    + "fingerprint, and signs a grant over the one the user confirms. That comparison is the "
                    + "only thing crossing between the two phones a person has to make, so the fingerprint is "
                    + "derived from the key rather than issued: both devices compute the same eight characters "
                    + "from the same 32 bytes.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Offered, with its fingerprint and its expiry",
                    content = @Content(schema = @Schema(
                            implementation = AccountAuthorityService.Candidate.class))),
            @ApiResponse(responseCode = "400", description = "invalid_device_key", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AccountAuthorityService.Candidate> offerCandidate(
            @RequestBody @Valid AuthorityCandidateRequest request) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        return ResponseEntity.ok(authorityService.registerCandidate(userId, request.getDeviceKeyB64(),
                request.getLabel()));
    }

    @GetMapping("/device/candidate")
    @Operation(summary = "The keys this account's new devices have offered",
            description = "For the device that will sign the grant. A grant over a key that is not a live "
                    + "candidate of this account is refused, so this list is what a grant may name.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The live candidates"),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<List<AccountAuthorityService.Candidate>> candidates() {
        return ResponseEntity.ok(
                authorityService.candidates(authenticatedUserAccessor.requireCurrentUserId()));
    }

    @PostMapping("/device/grant")
    @Operation(summary = "Activate another device key",
            description = "Takes effect on acceptance, because it only adds, and reserves no slot. The granted "
                    + "device is quarantined for one window: it may not sign a grant, a revocation or an "
                    + "approval, and it does not count toward the active device a revocation must leave behind. "
                    + "The new device generates its own key and never receives another device's.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Accepted, grantee quarantined until effectiveAt",
                    content = @Content(schema = @Schema(implementation = AuthoritySubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "invalid_authority_record", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_signer_refused, "
                    + "authority_device_quarantined or authority_native_session_required", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_position_refused, "
                    + "authority_pending_conflict or authority_head_conflict", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthoritySubmissionResponse> grantDevice(
            @RequestBody @Valid AuthorityRecordSubmission request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        Submitted submitted = authorityService.grantDevice(userId, authenticatedUserAccessor.currentClientId(),
                sessionHash(servletRequest), request.getRecord(), request.getSignature(), request.getChallenge());
        return accepted(submitted);
    }

    @PostMapping("/device/revoke")
    @Operation(summary = "Remove a device key",
            description = "Revoking another device waits out the window and is notified. Revoking itself takes "
                    + "effect at once, because a device removing its own authority reduces what an attacker "
                    + "holding it could do. Neither may leave the account with no unquarantined active device: "
                    + "an account with one device that wants to replace it goes through recovery, which installs "
                    + "the replacement in the same record.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending, or immediate for a self-revocation",
                    content = @Content(schema = @Schema(implementation = AuthoritySubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "invalid_authority_record", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_signer_refused or "
                    + "authority_device_quarantined", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_last_device, "
                    + "authority_position_refused or authority_head_conflict", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthoritySubmissionResponse> revokeDevice(
            @RequestBody @Valid AuthorityRecordSubmission request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        Submitted submitted = authorityService.revokeDevice(userId, authenticatedUserAccessor.currentClientId(),
                sessionHash(servletRequest), request.getRecord(), request.getSignature(), request.getChallenge());
        return accepted(submitted);
    }

    @PostMapping("/recover")
    @Operation(summary = "Replace the device set and the recovery key in one record",
            description = "Authorized by the committed recovery authority key, which runs ADM-002 D1's delay for "
                    + "framework 0x01 and cannot be cancelled by an active device, or through a completed "
                    + "account recovery, which is vetoable by the account immediately and is refused outright on "
                    + "a class 0x01 account. Both carry adoption's controls: the native app, the challenge "
                    + "inside the signature, a scoped step-up past the fresh-factor hold, and the refusal while "
                    + "a recent account recovery is inside that hold.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending, with its window",
                    content = @Content(schema = @Schema(implementation = AuthoritySubmissionResponse.class))),
            @ApiResponse(responseCode = "400", description = "invalid_authority_record", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_signer_refused or "
                    + "authority_native_session_required", content = @Content),
            @ApiResponse(responseCode = "409", description = "authority_position_refused or "
                    + "authority_pending_conflict", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthoritySubmissionResponse> recoverAuthority(
            @RequestBody @Valid AuthorityRecordSubmission request,
            @Parameter(hidden = true) HttpServletRequest servletRequest) {
        String userId = authenticatedUserAccessor.requireCurrentUserId();
        Submitted submitted = authorityService.recoverAuthority(userId,
                authenticatedUserAccessor.currentClientId(), sessionHash(servletRequest), request.getRecord(),
                request.getSignature(), request.getChallenge());
        return accepted(submitted);
    }

    @GetMapping
    @Operation(summary = "Read this account's authority chain",
            description = "The one endpoint that returns the account's permanent id, and only ever to its own "
                    + "account holder, because the client signs over its 34 raw bytes. Also reports the device "
                    + "set, any pending "
                    + "transition and the chain state. The class byte says how the id was derived and never "
                    + "whether the account holds authority today: a verifier that needs to know reads the chain.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The chain, the device set and any pending step",
                    content = @Content(schema = @Schema(
                            implementation = AuthorityAccounts.AuthorityStateResponse.class))),
            @ApiResponse(responseCode = "409", description = "authority_no_account", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthorityAccounts.AuthorityStateResponse> state() {
        return ResponseEntity.ok(authorityService.state(authenticatedUserAccessor.requireCurrentUserId()));
    }

    @PostMapping("/approval")
    @Operation(summary = "Start an approval a browser session cannot grant itself",
            description = "A browser login grants account access and never authority. This creates a pending "
                    + "approval carrying the account, the digest the server derives from the named action, and a "
                    + "challenge, and returns a four-character code from an alphabet with no look-alikes. An "
                    + "active authority device shows the same code and the action in the reader's own words and "
                    + "signs it. The digest is never taken from the caller, because the sentence on the screen "
                    + "and the bytes in the signature have to be the same action. The browser never learns a key "
                    + "and never proxies one.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Approval started",
                    content = @Content(schema = @Schema(implementation = AuthorityApprovalResponse.class))),
            @ApiResponse(responseCode = "409", description = "authority_approval_limit: three are already live",
                    content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<AuthorityApprovalResponse> startApproval(
            @RequestBody @Valid AuthorityApprovalStartRequest request) {
        policy.requireEnabled();
        AuthorityAccounts.Resolved account = accounts.require(authenticatedUserAccessor.requireCurrentUserId());
        AuthorityApprovalService.Started started =
                approvalService.start(account, request.getAction(), clock.instant());
        return ResponseEntity.ok(new AuthorityApprovalResponse(started.approvalId(), started.code(),
                started.challenge(), secondsUntil(started.expiresAt())));
    }

    @GetMapping("/approval")
    @Operation(summary = "The live approvals for this account",
            description = "At most three. An authority device fetches them, shows the code and the action, and "
                    + "signs one. A device refuses to present one while another is live, which is why the codes "
                    + "are unique among them.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The live approvals"),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<List<AuthorityApprovalView>> liveApprovals() {
        policy.requireEnabled();
        AuthorityAccounts.Resolved account = accounts.require(authenticatedUserAccessor.requireCurrentUserId());
        List<AuthorityApprovalView> views = approvalService.live(account, clock.instant()).stream()
                .map(approval -> new AuthorityApprovalView(approval.id(), approval.code(), approval.action(),
                        approval.actionDigest(), approval.challenge(), approval.expiresAt().getEpochSecond()))
                .toList();
        return ResponseEntity.ok(views);
    }

    @PostMapping("/approval/{approvalId}/sign")
    @Operation(summary = "Approve one pending action with a device signature",
            description = "Verified against every unquarantined active device key of the account. Single use, and "
                    + "burned on refusal as well as on acceptance, so the four-character code cannot be ground.",
            security = @SecurityRequirement(name = "oidcAccessToken"))
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Approved"),
            @ApiResponse(responseCode = "400", description = "authority_approval_invalid", content = @Content),
            @ApiResponse(responseCode = "403", description = "authority_approval_invalid", content = @Content),
            @ApiResponse(responseCode = "503", description = "authority_disabled", content = @Content)
    })
    public ResponseEntity<Void> signApproval(@PathVariable String approvalId,
            @RequestBody @Valid AuthorityApprovalSignRequest request) {
        policy.requireEnabled();
        AuthorityAccounts.Resolved account = accounts.require(authenticatedUserAccessor.requireCurrentUserId());
        approvalService.sign(account, approvalId, request.getSignature(), clock.instant());
        return ResponseEntity.noContent().build();
    }

    private static ResponseEntity<AuthoritySubmissionResponse> accepted(Submitted submitted) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new AuthoritySubmissionResponse(submitted.seq(),
                submitted.pending() ? "PENDING" : "ACTIVE", submitted.effectiveAtEpochSeconds(),
                submitted.recordHash()));
    }

    /**
     * Binds a challenge to the exact access token that asked for it.
     *
     * <p>Hashed, so nothing holds the token, and taken from the header rather than from anything the caller
     * sends beside it. A challenge minted for one session is therefore not spendable by another session of the
     * same account, which is what "held against that account and that stepped-up session" means.
     */
    private static String sessionHash(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return AuthorityChallengeService.sessionHash(header == null ? "" : header);
    }

    private long secondsUntil(Instant expiresAt) {
        return Math.max(Duration.between(clock.instant(), expiresAt).toSeconds(), 1L);
    }
}
