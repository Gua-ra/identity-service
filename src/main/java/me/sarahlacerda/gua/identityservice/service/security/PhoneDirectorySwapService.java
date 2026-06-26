package me.sarahlacerda.gua.identityservice.service.security;

import java.util.List;
import java.util.function.Function;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;

/**
 * The single atomic directory mapping switch for a phone-number change.
 *
 * <p>
 * Isolated in its own bean <em>on purpose</em>: the swap must run inside one
 * transaction, and a self-invocation from {@link PhoneChangeService} would be
 * routed straight to the target method, bypassing Spring's transactional proxy
 * and silently degrading the "atomic swap" into several independent auto-commit
 * transactions. Calling it across this bean boundary makes the proxy — and the
 * single transaction — actually engage.
 */
@Service
@RequiredArgsConstructor
public class PhoneDirectorySwapService {

    private final DirectoryService directoryService;
    private final UserSecurityService userSecurityService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;

    /**
     * Atomically switches the caller's directory mapping to {@code newE164},
     * carrying displayName/username/homeserverId/discoverable forward onto the new
     * digest and stamping the change-cooldown clock. Rejects with
     * {@link PhoneAlreadyLinkedException} (→ 409) when the target number is already
     * owned by another account. All mutations commit together or not at all.
     */
    @Transactional
    public void swap(String userId, String newE164) {
        String newDigest = phoneNumberHasher.digest(newE164);

        // Reject up-front when the target number already belongs to ANOTHER account.
        // upsertByDigest would otherwise find the foreign row and reassign its userId
        // via an UPDATE — the phone_digest is unchanged, so the UNIQUE constraint never
        // fires and the caller would silently hijack the victim's mapping. (Mirrors the
        // ownership guard the signup/login paths apply.)
        directoryService.findByDigest(newDigest)
                .filter(existing -> !userId.equals(existing.getUserId()))
                .ifPresent(existing -> {
                    throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
                });

        List<DirectoryEntry> currentEntries = directoryService.findByUserId(userId);

        // Carry-forward source: prefer a row that actually has the values populated
        // (the @Builder used by upsert omits username/homeserverId/discoverable).
        String displayName = firstNonBlank(currentEntries, DirectoryEntry::getDisplayName);
        String username = firstNonBlank(currentEntries, DirectoryEntry::getUsername);
        String homeserverId = firstNonBlank(currentEntries, DirectoryEntry::getHomeserverId);
        boolean discoverable = currentEntries.stream()
                .findFirst()
                .map(DirectoryEntry::isDiscoverable)
                .orElse(true);

        // Delete every old row except the (possibly already-present) new digest.
        currentEntries.stream()
                .map(DirectoryEntry::getPhoneDigest)
                .filter(digest -> !digest.equals(newDigest))
                .forEach(directoryService::deleteByDigest);

        try {
            directoryService.upsertByDigest(newDigest, phoneNumberMasker.mask(newE164), userId, displayName);
        } catch (DataIntegrityViolationException ex) {
            // Concurrent insert of the same brand-new digest by another account: the
            // UNIQUE constraint fires on INSERT. Surface as a 409.
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        // Carry routing + discovery opt-out forward (the @Builder dropped these).
        directoryService.assignRouting(newDigest, homeserverId, username);
        directoryService.setDiscoverable(newDigest, discoverable);

        // Start the cooldown clock atomically with the swap.
        userSecurityService.stampPhoneChange(userId);
    }

    private static String firstNonBlank(List<DirectoryEntry> entries, Function<DirectoryEntry, String> getter) {
        return entries.stream()
                .map(getter)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
    }
}
