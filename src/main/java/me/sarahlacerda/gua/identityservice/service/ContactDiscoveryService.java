package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
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
 *
 * <p>Privacy model: clients submit raw E.164 numbers over TLS; this service digests them in memory
 * with the peppered HMAC ({@link PhoneNumberHasher}) and matches against the at-rest digests. Raw
 * numbers are never persisted or logged. Client-side hashing is deliberately not used: the phone
 * keyspace is small enough that any digest a client could compute is reversible by dictionary.
 * Enumeration is limited by authentication, the per-request batch cap, the endpoint rate limit, a
 * per-account lookup budget that does not reset with the caller's address, and the per-account
 * discoverable opt-out.
 */
@Service
@RequiredArgsConstructor
public class ContactDiscoveryService {

    /** E.164: leading +, no leading zero, 7 to 15 digits total. */
    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{6,14}$");
    private static final String ACCOUNT_LOOKUPS_KEY_PREFIX = "directory:lookup:account:";

    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final IdentityServiceProperties properties;
    private final RateLimiter rateLimiter;

    /**
     * Matches the submitted phone numbers against discoverable accounts on behalf of {@code userId}.
     * Entries that are not valid E.164 are skipped so one bad contact does not fail the sync, duplicates
     * are collapsed, and batches above the configured cap are rejected. A call within the cap spends
     * one of the account's hourly lookups when that budget is configured.
     */
    public List<ContactMatch> match(String userId, List<String> phoneNumbers) {
        int maxBatch = properties.getDirectory().getMaxLookupBatch();
        if (phoneNumbers.size() > maxBatch) {
            throw new LookupBatchTooLargeException(
                    "At most " + maxBatch + " phone numbers can be matched per request");
        }
        int perAccount = properties.getDirectory().getMaxLookupsPerAccountPerHour();
        if (perAccount > 0) {
            rateLimiter.checkRate(ACCOUNT_LOOKUPS_KEY_PREFIX + userId, perAccount, Duration.ofHours(1));
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
