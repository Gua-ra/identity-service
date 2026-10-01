// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.Locale;

/** Every account lands in exactly one result. When several apply, declaration order decides. */
public enum PlacementShadowResult {

    MAS_NONE(true),

    /** One subject, two homeservers: a duplicate account. */
    MAS_MULTIPLE(true),

    /** The MAS username is not the localpart of the link subject: a merge onto a pre-existing MAS user. */
    MAS_USERNAME_MISMATCH(true),

    RECORD_DISAGREES(true),

    DIRECTORY_STALE(false),

    RECORD_MISSING(false),

    AGREE(false);

    private final boolean correctnessEvent;

    PlacementShadowResult(boolean correctnessEvent) {
        this.correctnessEvent = correctnessEvent;
    }

    /** True for results that block publishing for the account. */
    public boolean isCorrectnessEvent() {
        return correctnessEvent;
    }

    public String tag() {
        return name().toLowerCase(Locale.ROOT);
    }
}
