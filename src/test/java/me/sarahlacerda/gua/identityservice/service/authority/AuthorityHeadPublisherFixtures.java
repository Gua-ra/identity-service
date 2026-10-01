// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;

import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;
import me.sarahlacerda.gua.identityservice.service.placement.FederationIds;
import me.sarahlacerda.gua.identityservice.service.placement.RosterMembershipKeys;

import static org.mockito.Mockito.mock;

final class AuthorityHeadPublisherFixtures {

    private AuthorityHeadPublisherFixtures() {
    }

    static AuthorityHeadPublisher off(IdentityServiceProperties properties) {
        return new AuthorityHeadPublisher(properties, mock(AuthorityHeadPublicationRepository.class),
                mock(AuthorityHeadSigner.class), mock(ResolverAuthorityHeadClient.class),
                mock(AuthorityHeadPublications.class), new AuthorityAfterCommit(Runnable::run), Clock.systemUTC());
    }

    /** {@code publications} must be the container's proxy: its acknowledgement is written in REQUIRES_NEW. */
    static AuthorityHeadPublisher real(IdentityServiceProperties properties,
            AuthorityHeadPublicationRepository repository, AuthorityHeadPublications publications, Clock clock) {
        RosterMembershipKeys keys = new RosterMembershipKeys(properties, new FederationIds(properties));
        return new AuthorityHeadPublisher(properties, repository,
                new AuthorityHeadSigner(properties, keys),
                new ResolverAuthorityHeadClient(WebClient.builder(), properties),
                publications, new AuthorityAfterCommit(Runnable::run), clock);
    }
}
