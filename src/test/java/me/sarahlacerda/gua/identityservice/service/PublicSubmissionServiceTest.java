package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.PublicSubmission;
import me.sarahlacerda.gua.identityservice.repository.PublicSubmissionRepository;

@ExtendWith(MockitoExtension.class)
class PublicSubmissionServiceTest {

    @Mock
    private PublicSubmissionRepository repository;

    @Mock
    private GitHubIssueNotifier gitHubIssueNotifier;

    private PublicSubmissionService service;

    @BeforeEach
    void setUp() {
        IdentityServiceProperties props = new IdentityServiceProperties();
        props.getDirectory().setPepper("test-pepper");
        service = new PublicSubmissionService(repository, gitHubIssueNotifier, props);
    }

    @Test
    void recordSupportPersistsNormalizedAndOpensIssue() {
        service.recordSupport("  Ana Souza ", "  ANA@Example.com ", "  hello  ", "203.0.113.7");

        ArgumentCaptor<PublicSubmission> captor = ArgumentCaptor.forClass(PublicSubmission.class);
        verify(repository).save(captor.capture());
        PublicSubmission saved = captor.getValue();
        assertThat(saved.getType()).isEqualTo("support");
        assertThat(saved.getName()).isEqualTo("Ana Souza");
        assertThat(saved.getEmail()).isEqualTo("ana@example.com");
        assertThat(saved.getMessage()).isEqualTo("hello");
        // Raw IP is never stored: only a non-reversible digest.
        assertThat(saved.getSourceIpHash()).isNotNull().isNotEqualTo("203.0.113.7");

        verify(gitHubIssueNotifier).createIssue(contains("[support] from ana@example.com"), anyString());
    }

    @Test
    void recordBetaPersistsNormalizedAndOpensIssue() {
        service.recordBetaSignup("ANA@Example.com", "iOS", "203.0.113.7");

        ArgumentCaptor<PublicSubmission> captor = ArgumentCaptor.forClass(PublicSubmission.class);
        verify(repository).save(captor.capture());
        PublicSubmission saved = captor.getValue();
        assertThat(saved.getType()).isEqualTo("beta");
        assertThat(saved.getEmail()).isEqualTo("ana@example.com");
        assertThat(saved.getPlatform()).isEqualTo("ios");

        verify(gitHubIssueNotifier).createIssue(contains("[beta] ana@example.com (ios)"), anyString());
    }

    @Test
    void submissionStillPersistsWhenGitHubNotificationFails() {
        when(gitHubIssueNotifier.createIssue(anyString(), anyString()))
                .thenThrow(new RuntimeException("github down"));

        // Must not propagate: persistence is the source of truth.
        service.recordBetaSignup("ana@example.com", "android", "203.0.113.7");

        verify(repository).save(org.mockito.ArgumentMatchers.any(PublicSubmission.class));
    }
}
