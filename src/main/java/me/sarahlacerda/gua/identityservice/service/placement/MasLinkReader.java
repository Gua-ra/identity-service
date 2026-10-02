package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;
import java.util.Map;

/**
 * Reads placement evidence out of each homeserver's MAS.
 *
 * <p>Each MAS owns {@code users} and {@code upstream_oauth_links}, and those links are the only
 * committed evidence of where an account lives.
 *
 * <p>Both implementations are off by default and report {@link #isConfigured()} false until an
 * operator turns one on. With neither configured the reconciler refuses to run instead of reporting
 * every account as having no MAS link.
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
     * Empty when the path cannot see it: the MAS admin API's provider model omits
     * {@code claims_imports}, so only the SQL path can answer.
     */
    Map<String, String> localpartOnConflictByHomeserver();
}
