package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

/**
 * Regression guard for ADM-001 L1b. This service used to publish {@code phone -> homeserver}
 * rows into the gua-resolver directory with a client that signed each write with this
 * homeserver's roster key; the resolver accepted any active member's key for any row, so a
 * member could bind any phone number to itself. That client is deleted, not disabled.
 *
 * <p>The guard scans every compiled class of the service, main and test alike, for the
 * strings the removed mechanism needed and fails if any of them comes back: the resolver
 * write endpoint, the client type, and its canonical signing prefix.
 */
class ResolverDirectoryPublishRemovedTest {

    private static final String SERVICE_CLASSES = "classpath*:me/sarahlacerda/gua/identityservice/**/*.class";

    /** Assembled at runtime so the needles never sit in this class's own constant pool. */
    private static final List<String> FORBIDDEN = List.of(
            String.join("/", "", "directory", "entries"),
            String.join("", "Resolver", "Directory", "Client"),
            String.join(".", "directory-write", "v1"));

    @Test
    void noClassReferencesTheResolverDirectoryWritePath() throws IOException {
        Resource[] classes = new PathMatchingResourcePatternResolver().getResources(SERVICE_CLASSES);
        assertThat(classes).isNotEmpty();

        String self = getClass().getSimpleName();
        List<String> offenders = new ArrayList<>();
        for (Resource clazz : classes) {
            String fileName = clazz.getFilename();
            if (fileName != null && fileName.startsWith(self)) {
                continue;
            }
            String constantPool = new String(clazz.getContentAsByteArray(), StandardCharsets.ISO_8859_1);
            for (String needle : FORBIDDEN) {
                if (constantPool.contains(needle)) {
                    offenders.add(clazz.getDescription() + " references " + needle);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void resolverPropertiesAreGone() {
        assertThat(IdentityServiceProperties.class.getDeclaredClasses())
                .extracting(Class::getSimpleName)
                .doesNotContain("ResolverProperties");
        assertThat(IdentityServiceProperties.class.getMethods())
                .extracting(Method::getName)
                .doesNotContain("getResolver");
    }
}
