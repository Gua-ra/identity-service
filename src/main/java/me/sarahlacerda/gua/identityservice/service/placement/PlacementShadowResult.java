package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Locale;

/**
 * The closed classification vocabulary of the shadow comparison. Every account lands in exactly one
 * result.
 *
 * <p>The definitions overlap (one MAS link, an agreeing directory and no published record is both
 * {@code agree} and {@code record_missing}), so declaration order decides: correctness events first,
 * then the data-quality finding, then the missing record, then agreement. Publishing is decided
 * separately and does not follow that order.
 */
public enum PlacementShadowResult {

    /**
     * No MAS link at all: the account has never completed a delegated login. Nothing is published for
     * it until it logs in once, because the MAS link is the only committed evidence of placement.
     */
    MAS_NONE(true),

    /**
     * One subject, two homeservers: a duplicate account. Either two MAS instances hold a link for it, or
     * the Matrix user id names a homeserver other than the one holding its link. Publishes nothing.
     */
    MAS_MULTIPLE(true),

    /**
     * The MAS username is not the localpart of the link subject: evidence of a merge onto a
     * pre-existing MAS user through the localpart import running with {@code on_conflict: add}.
     */
    MAS_USERNAME_MISMATCH(true),

    /**
     * A published record names a different homeserver than the evidence does. Never overwritten: either
     * a duplicate identity or a bad signer.
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

    /** True for results that block publishing for the account. */
    public boolean isCorrectnessEvent() {
        return correctnessEvent;
    }

    /** The metric tag and log value, e.g. {@code mas_username_mismatch}. */
    public String tag() {
        return name().toLowerCase(Locale.ROOT);
    }
}
