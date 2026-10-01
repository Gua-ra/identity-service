package me.sarahlacerda.gua.identityservice.service.security;

import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/**
 * Maps a passkey to its stable account principal, and a principal to the account's current Matrix user id.
 * The only passkey class that may name an accountId; {@code AccountIdNotReadGuardTest} enforces it.
 */
@Component
@RequiredArgsConstructor
public class PasskeyPrincipals {

    private final AccountGenesisRepository genesisRepository;

    /** {@code text} is the canonical accountId stored in the database; {@code bytes} are the WebAuthn user handle. */
    public record Principal(String text, byte[] bytes) {
    }

    /** Empty when the account has no attached genesis row. Callers must refuse. */
    @Transactional(readOnly = true)
    public Optional<Principal> forUserId(String userId) {
        if (userId == null || userId.isBlank()) {
            return Optional.empty();
        }
        return genesisRepository.findByUserId(userId)
                .filter(row -> row.getState() == AccountGenesisRecord.State.ATTACHED)
                .map(AccountGenesisRecord::getAccountId)
                .map(this::parse);
    }

    @Transactional(readOnly = true)
    public Optional<String> currentUserId(String principalText) {
        if (principalText == null || principalText.isBlank()) {
            return Optional.empty();
        }
        return genesisRepository.findById(principalText)
                .filter(row -> row.getState() == AccountGenesisRecord.State.ATTACHED)
                .map(AccountGenesisRecord::getUserId)
                .filter(id -> id != null && !id.isBlank());
    }

    /** Empty for bytes that are not a canonical accountId, such as the Matrix id an older credential replays. */
    public Optional<Principal> fromHandleBytes(byte[] handle) {
        try {
            AccountId id = AccountId.fromRawBytes(handle);
            return Optional.of(new Principal(id.value(), id.rawBytes()));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    /** Empty when the text is not a canonical accountId. */
    public Optional<Principal> fromText(String principalText) {
        if (principalText == null || principalText.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(parse(principalText));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    /** Throws when the text is not a canonical accountId. For stored principals only. */
    public Principal parse(String principalText) {
        AccountId id = AccountId.parse(principalText);
        return new Principal(id.value(), id.rawBytes());
    }
}
