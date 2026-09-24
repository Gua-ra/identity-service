// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;

import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;
import me.sarahlacerda.gua.identityservice.service.placement.FederationIds;
import me.sarahlacerda.gua.identityservice.service.placement.RosterMembershipKeys;

import static org.mockito.Mockito.mock;

/** Builds the head publisher the way a test needs it, so no test spells six collaborators. */
final class AuthorityHeadPublisherFixtures {

    private AuthorityHeadPublisherFixtures() {
    }

    /**
     * A real publisher with publishing switched off, for the classes that are about something else.
     *
     * <p>The collaborators are mocks and never called: {@code publishSettledHead} reads the flag and returns
     * before it looks at a repository, a signer or a client. A class using this therefore also demonstrates
     * that the chain runs untouched with the publication flag off, which is the point of having the two
     * flags.
     */
    static AuthorityHeadPublisher off(IdentityServiceProperties properties) {
        return new AuthorityHeadPublisher(properties, mock(AuthorityHeadPublicationRepository.class),
                mock(AuthorityHeadSigner.class), mock(ResolverAuthorityHeadClient.class),
                mock(AuthorityHeadPublications.class), Clock.systemUTC());
    }

    /**
     * A real publisher, wired the way the container wires it, against whatever the properties say.
     *
     * <p>{@code publications} is passed in rather than built here because it has to be the container's own
     * proxy: the acknowledgement is written in a {@code REQUIRES_NEW} transaction, and an instance built with
     * {@code new} would run that write with no transaction at all, joining the persistence context of the
     * transaction that has just committed and never flushing.
     */
    static AuthorityHeadPublisher real(IdentityServiceProperties properties,
            AuthorityHeadPublicationRepository repository, AuthorityHeadPublications publications, Clock clock) {
        RosterMembershipKeys keys = new RosterMembershipKeys(properties, new FederationIds(properties));
        return new AuthorityHeadPublisher(properties, repository,
                new AuthorityHeadSigner(properties, keys),
                new ResolverAuthorityHeadClient(WebClient.builder(), properties),
                publications, clock);
    }
}
