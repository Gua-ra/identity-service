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

// A separate bean so the swap runs in one transaction: a self-invocation from PhoneChangeService would bypass
// the proxy.
@Service
@RequiredArgsConstructor
public class PhoneDirectorySwapService {

    private final DirectoryService directoryService;
    private final UserSecurityService userSecurityService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final PhoneNumberMasker phoneNumberMasker;

    @Transactional
    public void swap(String userId, String newE164) {
        String newDigest = phoneNumberHasher.digest(newE164);

        // Reject a number owned by another account first: upsertByDigest would otherwise reassign that row
        // without tripping the UNIQUE constraint.
        directoryService.findByDigest(newDigest)
                .filter(existing -> !userId.equals(existing.getUserId()))
                .ifPresent(existing -> {
                    throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
                });

        List<DirectoryEntry> currentEntries = directoryService.findByUserId(userId);

        // The upsert builder omits username, homeserverId and discoverable, so they are carried forward
        // explicitly.
        String displayName = firstNonBlank(currentEntries, DirectoryEntry::getDisplayName);
        String username = firstNonBlank(currentEntries, DirectoryEntry::getUsername);
        String homeserverId = firstNonBlank(currentEntries, DirectoryEntry::getHomeserverId);
        boolean discoverable = currentEntries.stream()
                .findFirst()
                .map(DirectoryEntry::isDiscoverable)
                .orElse(true);

        currentEntries.stream()
                .map(DirectoryEntry::getPhoneDigest)
                .filter(digest -> !digest.equals(newDigest))
                .forEach(directoryService::deleteByDigest);

        try {
            directoryService.upsertByDigest(newDigest, phoneNumberMasker.mask(newE164), userId, displayName);
        } catch (DataIntegrityViolationException ex) {
            // A concurrent insert of the same digest trips the UNIQUE constraint.
            throw new PhoneAlreadyLinkedException("Phone number already linked to another account");
        }

        directoryService.assignRouting(newDigest, homeserverId, username);
        directoryService.setDiscoverable(newDigest, discoverable);

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
