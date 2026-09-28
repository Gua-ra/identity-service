package me.sarahlacerda.gua.identityservice.service.security;

import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

/**
 * The one seam between a passkey and the stable Gua account it belongs to.
 *
 * <p>A passkey must belong to an identity that outlives the account's current Matrix name. The MXID is not
 * that identity: it contains the localpart and the homeserver domain, so it changes when placement changes,
 * and until this seam existed it was both the ownership key of every credential row and the WebAuthn user
 * handle itself, which the authenticator stores and replays on every assertion.
 *
 * <p>So the direction of resolution is inverted. A credential resolves to a principal, and only then does
 * anything ask what Matrix identity that principal currently has. Nothing in the WebAuthn layer sees an
 * MXID any more.
 *
 * <p><b>Why this is the only new file that names an accountId.</b> {@code AccountIdNotReadGuardTest} allows a
 * small set of files to name one at all, and forbids it outright on the routing and login path. The hazard it
 * states is specific: MAS derives the Matrix localpart from a Jinja template over the imported claims, and an
 * accountId would pass MAS's localpart rules, so an accountId reaching a claim, a userinfo field or a
 * directory column is one deploy away from re-keying accounts. A WebAuthn user handle is none of those. This
 * class is therefore added to that test's allow list and exposes {@link Principal}, whose name carries no
 * "accountId", so {@code PasskeyService} never names one and stays outside the allow list. The precedent is
 * {@code AuthorityAccounts}, which the account-authority feature added the same way: exactly one seam.
 */
@Component
@RequiredArgsConstructor
public class PasskeyPrincipals {

    private final AccountGenesisRepository genesisRepository;

    /**
     * A stable account principal, opaque to everything above this class.
     *
     * @param text  the canonical accountId spelling, which is what the database column stores
     * @param bytes the 34 canonical bytes, which are what the WebAuthn user handle carries
     */
    public record Principal(String text, byte[] bytes) {
    }

    /**
     * The principal of the account currently known by this Matrix user id.
     *
     * <p>Empty when the account has no attached genesis row. Callers must refuse rather than fall back to
     * the MXID: a credential written under an MXID is exactly the thing being removed, and writing one
     * "just this once" would reintroduce a row that no placement change can survive.
     */
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

    /**
     * The Matrix user id this principal currently resolves to.
     *
     * <p>"Currently" is the whole point. The login flow and MAS still need an MXID, so one is produced here,
     * at the boundary, from the genesis row rather than from the credential. A credential therefore keeps
     * working across a change of Matrix identity, because it never recorded one.
     */
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

    /**
     * The principal these canonical bytes name, or empty when they name none.
     *
     * <p>Empty rather than throwing, because the bytes arrive from an authenticator: a credential registered
     * under the old model replays a handle that is an MXID's own bytes, which is not 34 bytes and does not
     * begin with the format version, so it cannot be mistaken for a principal. That is also why this model
     * needs no version column on the row. The caller turns the empty into a refusal.
     */
    public Optional<Principal> fromHandleBytes(byte[] handle) {
        try {
            AccountId id = AccountId.fromRawBytes(handle);
            return Optional.of(new Principal(id.value(), id.rawBytes()));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    /**
     * A principal from text that may not be one, without throwing.
     *
     * <p>Used where the text arrives from the WebAuthn library as a "username": for a credential registered
     * under the old model that value is an MXID, which is not a canonical accountId, so the answer is empty
     * and the ceremony fails closed.
     */
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

    /** Parses a stored principal, which this service wrote, so a bad value is a programming error. */
    public Principal parse(String principalText) {
        AccountId id = AccountId.parse(principalText);
        return new Principal(id.value(), id.rawBytes());
    }
}
