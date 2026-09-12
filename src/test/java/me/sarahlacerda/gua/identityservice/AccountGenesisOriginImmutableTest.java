package me.sarahlacerda.gua.identityservice;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Locale;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code origin} is the audit marker ADM-001 L5 rests on: it says whether an account's identity is
 * rooted in a genesis the client proved possession of, or is a bootstrap id this deployment minted for
 * an account that predates the feature. An auditor can only rely on that split if nothing can flip it
 * after the fact, so a bootstrap account is not adopted into a rooted one in this phase.
 *
 * <p>The javadoc on {@link AccountGenesisRepository} claims this test enforces that. It does, from three
 * directions: no mutator on the entity, no repository method that names the field, and no modifying
 * query that writes the column.
 */
class AccountGenesisOriginImmutableTest {

    /** The only mutable fields on the row: re-registering a pending genesis rotates the pair. */
    private static final List<String> ALLOWED_SETTERS = List.of("setAttachHandleHash", "setExpiresAt");

    @Test
    void theEntityExposesNoSetterBeyondTheHandleAndItsWindow() {
        List<String> setters = Arrays.stream(AccountGenesisRecord.class.getMethods())
                .map(Method::getName)
                .filter(name -> name.startsWith("set"))
                .sorted()
                .toList();

        // An allowlist rather than a check for setOrigin by name: a class-level @Setter puts a mutator on
        // every field at once, which is how origin became settable in the first place.
        assertThat(setters).containsExactlyInAnyOrderElementsOf(ALLOWED_SETTERS);
    }

    @Test
    void noMethodOnTheEntityTakesAnOrigin() {
        List<String> takingAnOrigin = Arrays.stream(AccountGenesisRecord.class.getMethods())
                .filter(method -> Arrays.asList(method.getParameterTypes()).contains(Origin.class))
                .map(Method::getName)
                .toList();

        assertThat(takingAnOrigin).isEmpty();
    }

    @Test
    void theRepositoryNamesOriginOnlyToCountIt() {
        List<String> naming = Arrays.stream(AccountGenesisRepository.class.getDeclaredMethods())
                .map(Method::getName)
                .filter(name -> name.toLowerCase(Locale.ROOT).contains("origin"))
                .filter(name -> !name.equals("countByOrigin"))
                .toList();

        // countByOrigin reads, for the audit split gauge. A derived deleteBy/removeBy or any other
        // method naming the field would be a write path.
        assertThat(naming).isEmpty();
    }

    @Test
    void noModifyingQueryWritesTheOriginColumn() {
        for (Method method : AccountGenesisRepository.class.getDeclaredMethods()) {
            Query query = method.getAnnotation(Query.class);
            if (query == null || method.getAnnotation(Modifying.class) == null) {
                continue;
            }
            assertThat(query.value().toLowerCase(Locale.ROOT))
                    .as("modifying query %s must not write origin", method.getName())
                    .doesNotContain("origin");
        }
    }
}
