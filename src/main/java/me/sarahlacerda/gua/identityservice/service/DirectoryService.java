package me.sarahlacerda.gua.identityservice.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import lombok.AllArgsConstructor;
import me.sarahlacerda.gua.identityservice.domain.DirectoryMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;

@Service
@AllArgsConstructor
public class DirectoryService {

    private static final Logger log = LoggerFactory.getLogger(DirectoryService.class);

    private final DirectoryEntryRepository repository;

    /**
     * Upsert a directory entry. A {@code null} {@code displayName} preserves the existing value
     * (no overwrite); pass an empty string to clear it explicitly.
     */
    @Transactional
    public DirectoryEntry upsertByDigest(String phoneDigest, String userId, String displayName) {
        return upsertByDigest(phoneDigest, null, userId, displayName);
    }

    /**
     * Upsert a directory entry, also persisting a display-only masked phone.
     * A {@code null} {@code phoneMasked} or {@code displayName} preserves the
     * existing value (no overwrite).
     */
    @Transactional
    public DirectoryEntry upsertByDigest(String phoneDigest, String phoneMasked, String userId, String displayName) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
            .map(existing -> updateExisting(existing, phoneMasked, userId, displayName))
            .orElseGet(() -> DirectoryEntry.builder()
                .phoneDigest(phoneDigest)
                .phoneMasked(phoneMasked)
                .userId(userId)
                .displayName(displayName)
                .build());
        return repository.save(entry);
    }

    private DirectoryEntry updateExisting(DirectoryEntry entry, String phoneMasked, String userId, String displayName) {
        entry.setUserId(userId);
        if (phoneMasked != null) {
            entry.setPhoneMasked(phoneMasked);
        }
        if (displayName != null) {
            entry.setDisplayName(displayName);
        } else if (entry.getDisplayName() != null) {
            log.debug("Preserving existing display name for user {} (null displayName in upsert)", userId);
        }
        return entry;
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> findByDigest(String phoneDigest) {
        return repository.findByPhoneDigest(phoneDigest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryMatch> lookupMatches(Collection<String> digests) {
        return repository.findByPhoneDigestIn(digests).stream()
            .map(entry -> new DirectoryMatch(entry.getPhoneDigest(), entry.getUserId(), entry.getDisplayName()))
            .toList();
    }

    @Transactional
    public void deleteByDigest(String digest) {
        repository.deleteByPhoneDigest(digest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryEntry> findByUserId(String userId) {
        return repository.findByUserId(userId);
    }

    /**
     * Returns the display-only masked phone (e.g. "••••4567") linked to the user,
     * or empty when none is recorded. Never exposes the full number.
     */
    @Transactional(readOnly = true)
    public Optional<String> findMaskedPhoneByUserId(String userId) {
        return repository.findByUserId(userId).stream()
            .map(DirectoryEntry::getPhoneMasked)
            .filter(masked -> masked != null && !masked.isBlank())
            .findFirst();
    }
}
