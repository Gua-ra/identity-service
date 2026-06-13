package me.sarahlacerda.gua.identityservice.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import lombok.AllArgsConstructor;
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
     * Upsert a directory entry. A {@code null} {@code displayName} preserves the
     * existing value
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

    /**
     * Contact discovery: resolves phone digests to directory entries, excluding
     * accounts that opted out of discovery ({@code discoverable = false}).
     */
    @Transactional(readOnly = true)
    public List<DirectoryEntry> findDiscoverableByDigests(Collection<String> digests) {
        return repository.findByPhoneDigestInAndDiscoverableTrue(digests);
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

    // --- Routing-at-scale (Gua federation) -------------------------------------

    /**
     * Records the routing decision for an account: which homeserver it lives on and
     * the globally-unique username alias. Looked up by phone digest (the account's
     * stable directory key). A {@code null} value leaves the existing column
     * untouched so this is safe to call on re-link.
     */
    @Transactional
    public DirectoryEntry assignRouting(String phoneDigest, String homeserverId, String username) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
                .orElseThrow(() -> new IllegalStateException(
                        "Cannot assign routing: no directory entry for the given phone digest"));
        if (homeserverId != null) {
            entry.setHomeserverId(homeserverId);
        }
        if (username != null) {
            entry.setUsername(username);
        }
        return repository.save(entry);
    }

    /** True when the (case-insensitive) global username is already taken. */
    @Transactional(readOnly = true)
    public boolean isUsernameTaken(String username) {
        return repository.existsByUsernameIgnoreCase(username);
    }

    /**
     * Resolves a global username to its directory entry (Matrix user id +
     * homeserver). This is the routing lookup that lets the federation find where a
     * given identity lives.
     */
    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> resolveByUsername(String username) {
        return repository.findByUsernameIgnoreCase(username);
    }
}
