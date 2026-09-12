// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Locale;

/**
 * The closed classification vocabulary of the shadow comparison (ADM-008 decision 9). Every account
 * lands in exactly one of these, and the Phase 4 exit criteria are stated in these words.
 *
 * <p>The brief's definitions overlap: an account with one MAS link, an agreeing directory and no
 * published record satisfies both {@code agree} and {@code record_missing}, and one with a stale
 * directory and no record satisfies both {@code directory_stale} and {@code record_missing}. Exactly one
 * result per account therefore needs an order, and the order is declaration order below: the correctness
 * events first, because they block the phase exit and have to be explained account by account, then the
 * data-quality finding, then the missing record, then agreement. Publishing does not follow that order
 * and is decided separately, so a stale directory row does not stop a record being published for an
 * account whose evidence is otherwise clean.
 */
public enum PlacementShadowResult {

    /**
     * No MAS link at all: the account has never completed a delegated login. Nothing is published for
     * it until it logs in once, because the MAS link is the only committed evidence of placement.
     */
    MAS_NONE(true),

    /**
     * One subject, two homeservers. Either two MAS instances hold a link for it, or the Matrix user id
     * names a homeserver other than the one holding its link. Both shapes are the same finding, a
     * duplicate account, and both are alerted on and publish nothing. The structured log line carries
     * which shape it was.
     */
    MAS_MULTIPLE(true),

    /**
     * The MAS username is not the localpart of the link subject: evidence of a merge onto a
     * pre-existing MAS user through the localpart import running with {@code on_conflict: add}.
     */
    MAS_USERNAME_MISMATCH(true),

    /**
     * A published record names a different homeserver than the evidence does. Never overwritten: either
     * a duplicate identity or a bad signer, and moving an account is refused outright.
     */
    RECORD_DISAGREES(true),

    /**
     * This service's local routing choice disagrees with where the account actually lives. A
     * data-quality finding, not a security event: the local choice is not a committed placement and
     * nothing outside this service can re-derive it.
     */
    DIRECTORY_STALE(false),

    /** The evidence is clean and no record has been published yet. */
    RECORD_MISSING(false),

    /** One home, the directory agrees, and the published record agrees or is about to be written. */
    AGREE(false);

    private final boolean correctnessEvent;

    PlacementShadowResult(boolean correctnessEvent) {
        this.correctnessEvent = correctnessEvent;
    }

    /**
     * True for the results that block the Phase 4 exit until explained, and that stop a record being
     * published for the account.
     */
    public boolean isCorrectnessEvent() {
        return correctnessEvent;
    }

    /** The metric tag and log value, e.g. {@code mas_username_mismatch}. */
    public String tag() {
        return name().toLowerCase(Locale.ROOT);
    }
}
