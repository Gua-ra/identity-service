package me.sarahlacerda.gua.identityservice.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.ContactMatch;
import me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException;

/**
 * Address-book contact discovery.
 * <p>
 * Privacy model: clients submit raw E.164 numbers over TLS; this service digests
 * them in memory with the server-side peppered HMAC ({@link PhoneNumberHasher})
 * and matches against the at-rest digests. Raw numbers are never persisted and
 * must never be logged. Client-side hashing is deliberately NOT used: the phone
 * number keyspace is small enough that any digest a client could compute (with a
 * necessarily public key) is reversible by dictionary, while shipping the secret
 * pepper to clients would let anyone with a database dump reverse the at-rest
 * digests. Enumeration abuse is mitigated by authentication, the per-request
 * batch cap and the endpoint rate limit, plus the per-account discoverable
 * opt-out.
 */
@Service
@RequiredArgsConstructor
public class ContactDiscoveryService {

    /** E.164: leading +, no leading zero, 7–15 digits total. */
    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{6,14}$");

    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final IdentityServiceProperties properties;

    /**
     * Matches the submitted phone numbers against discoverable Gua accounts.
     * Entries that are not valid E.164 are silently skipped (address books are
     * messy; one bad entry must not fail the sync), duplicates are collapsed, and
     * batches above the configured cap are rejected.
     */
    public List<ContactMatch> match(List<String> phoneNumbers) {
        int maxBatch = properties.getDirectory().getMaxLookupBatch();
        if (phoneNumbers.size() > maxBatch) {
            throw new LookupBatchTooLargeException(
                    "At most " + maxBatch + " phone numbers can be matched per request");
        }
        Map<String, String> phoneByDigest = new LinkedHashMap<>();
        for (String phone : phoneNumbers) {
            if (phone != null && E164.matcher(phone).matches()) {
                phoneByDigest.putIfAbsent(phoneNumberHasher.digest(phone), phone);
            }
        }
        if (phoneByDigest.isEmpty()) {
            return List.of();
        }
        return directoryService.findDiscoverableByDigests(phoneByDigest.keySet()).stream()
                .map(entry -> new ContactMatch(
                        phoneByDigest.get(entry.getPhoneDigest()),
                        entry.getUserId(),
                        entry.getUsername(),
                        entry.getDisplayName()))
                .toList();
    }
}
