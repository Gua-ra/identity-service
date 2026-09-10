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
     * Records this deployment's routing choice for an account: the homeserver it was
     * created on and the username alias, which is unique within this directory only.
     * Looked up by phone digest (the account's stable directory key). A {@code null}
     * value leaves the existing column untouched so this is safe to call on re-link.
     * The row is a local record, not the committed placement or identifier binding of
     * <a href="https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md">ADM-001</a>
     * (L6, L7).
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

    /**
     * Sets the contact-discovery opt-out flag on the entry for {@code phoneDigest}.
     * The {@code @Builder} does not carry {@code discoverable}, so a phone change
     * (which builds a fresh row for the new digest) must call this to preserve a
     * user's prior discovery opt-out instead of silently re-opting them in.
     */
    @Transactional
    public DirectoryEntry setDiscoverable(String phoneDigest, boolean discoverable) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
                .orElseThrow(() -> new IllegalStateException(
                        "Cannot set discoverable: no directory entry for the given phone digest"));
        entry.setDiscoverable(discoverable);
        return repository.save(entry);
    }

    /** True when the (case-insensitive) global username is already taken. */
    @Transactional(readOnly = true)
    public boolean isUsernameTaken(String username) {
        return repository.existsByUsernameIgnoreCase(username);
    }

    /**
     * Resolves a username to its directory entry (Matrix user id + the homeserver
     * recorded for it in this deployment's directory). Uniqueness is enforced within
     * this directory, not across the federation: federation-wide uniqueness is a
     * property of the sequenced binding log in ADM-001 (L11, L12). Routing before
     * login is the resolver's own lookup, in which this service takes no part.
     */
    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> resolveByUsername(String username) {
        return repository.findByUsernameIgnoreCase(username);
    }
}
