// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;
import java.util.Map;

/**
 * Reads placement evidence out of each homeserver's MAS.
 *
 * <p>Each MAS owns {@code users} and {@code upstream_oauth_links}, and those links are the only
 * committed evidence of where an account actually lives: this service's own directory holds a local
 * routing choice that nothing outside it can re-derive, and the Matrix user id is a name, not a proof.
 *
 * <p>Two implementations exist because the deployment has granted neither access path yet. Both are off
 * by default and both report {@link #isConfigured()} false until an operator turns one on, at which
 * point the reconciler uses it. With neither configured the reconciler refuses to run and says so,
 * rather than reporting every account as having no MAS link, which would look like a finding.
 */
public interface MasLinkReader {

    /** True when this deployment has actually been given this read path. */
    boolean isConfigured();

    /** Short description of the path, for the log line that says which one ran. */
    String describe();

    /**
     * Every link this subject holds, across every configured homeserver. A subject with links on two
     * homeservers is the duplicate-account symptom the comparison exists to surface.
     */
    List<MasLink> linksFor(String subject);

    /**
     * Each MAS's effective {@code claims_imports.localpart.on_conflict}, by roster homeserver id.
     *
     * <p>Empty when the path cannot see it. The MAS admin API's provider model omits
     * {@code claims_imports}, so only the SQL path or the rendered configuration can answer, and the
     * gauge built on this is how an operator notices {@code add} coming back after it was set to
     * {@code fail}.
     */
    Map<String, String> localpartOnConflictByHomeserver();
}
