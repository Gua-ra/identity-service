// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;
import java.util.Map;

/** MAS upstream_oauth_links rows are the only committed evidence of where an account lives. */
public interface MasLinkReader {

    boolean isConfigured();

    String describe();

    /** A subject with links on two homeservers is a duplicate account. */
    List<MasLink> linksFor(String subject);

    /** Empty when the path cannot see claims_imports. */
    Map<String, String> localpartOnConflictByHomeserver();
}
