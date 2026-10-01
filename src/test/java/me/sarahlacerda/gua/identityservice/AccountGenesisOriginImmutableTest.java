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

class AccountGenesisOriginImmutableTest {

    private static final List<String> ALLOWED_SETTERS = List.of("setAttachHandleHash", "setExpiresAt");

    @Test
    void theEntityExposesNoSetterBeyondTheHandleAndItsWindow() {
        List<String> setters = Arrays.stream(AccountGenesisRecord.class.getMethods())
                .map(Method::getName)
                .filter(name -> name.startsWith("set"))
                .sorted()
                .toList();

        // An allowlist: a class-level @Setter would put a mutator on every field at once.
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
