package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;

import me.sarahlacerda.gua.identityservice.domain.MatrixIds;

/**
 * Regression guard for ADM-001 S6. Returning users used to present
 * {@code localpartOf(userId)} to MAS as {@code preferred_username}: the text before the
 * first colon of whatever the user id was. With the MAS claims import set to
 * {@code on_conflict: add}, re-keying {@code user_id} to a colon-bearing value, or any
 * other change that gives two accounts one localpart, links each such account onto a
 * single MAS user. The localpart now comes from the username stored in the directory,
 * chosen by {@code AccountLocalpartResolver}, with {@code MatrixIds} as its strict
 * fallback parser.
 *
 * <p>The guard fails if a localpart derivation from a user id comes back: a class
 * declaring its own {@code localpartOf}, main code splitting a user id on its colon, a
 * caller of the parser other than the resolver, or a {@code setPreferredUsername} whose
 * value comes from anywhere but the resolver or the handle a new user just chose.
 */
class LocalpartDerivationGuardTest {

    private static final String SERVICE_CLASSES = "classpath*:me/sarahlacerda/gua/identityservice/**/*.class";
    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");

    private static final String PARSE_METHOD = "localpartOf";
    private static final String PARSER_FILE = "MatrixIds.java";
    private static final String RESOLVER_FILE = "AccountLocalpartResolver.java";
    private static final String RESOLVE_CALL = "accountLocalparts.forExistingAccount(";
    private static final String NEW_HANDLE_CALL = "usernamePolicy.normalizeAndValidate(";

    /** A user-id-like expression followed by string surgery on it. */
    private static final Pattern USER_ID_SURGERY = Pattern.compile(
            "\\b(?:\\w*[uU]serId|\\w*[mM]xid|\\w*[mM]atrixId|subject)(?:\\(\\))?\\s*\\.\\s*"
                    + "(?:indexOf|lastIndexOf|split|substring|replaceFirst|replaceAll|replace)\\s*\\(");

    /**
     * Reviewed exceptions. These lines read the server name after the colon (the Matrix
     * domain reported for legacy directory rows), never the localpart.
     */
    private static final Map<String, Set<String>> SURGERY_ALLOWED = Map.of(
            "DirectoryController.java", Set.of(
                    "int colon = userId.indexOf(':');",
                    "return colon >= 0 ? userId.substring(colon + 1) : null;"));

    private static final Pattern SET_PREFERRED_USERNAME = Pattern.compile("setPreferredUsername\\(([^;]*)\\);");

    /**
     * The only argument forms allowed per file, whitespace removed. {@code localpart} is
     * the handle a brand-new user just chose in {@code /login/profile}; {@code
     * preferredUsername} must be assigned from the resolver (checked below).
     */
    private static final Map<String, Set<String>> PREFERRED_USERNAME_ALLOWED = Map.of(
            "LoginFlowController.java", Set.of("localpart", "preferredUsername"),
            "SecurityController.java", Set.of("preferredUsername"));

    @Test
    void onlyMatrixIdsDeclaresALocalpartParser() throws Exception {
        Resource[] classes = new PathMatchingResourcePatternResolver().getResources(SERVICE_CLASSES);
        assertThat(classes).isNotEmpty();

        MetadataReaderFactory readers = new SimpleMetadataReaderFactory();
        ClassLoader loader = getClass().getClassLoader();
        List<String> offenders = new ArrayList<>();
        for (Resource resource : classes) {
            String className = readers.getMetadataReader(resource).getClassMetadata().getClassName();
            Class<?> type = Class.forName(className, false, loader);
            if (type == MatrixIds.class) {
                continue;
            }
            for (Method method : type.getDeclaredMethods()) {
                if (method.getName().equals(PARSE_METHOD)) {
                    offenders.add(className + " declares " + PARSE_METHOD);
                }
            }
        }

        assertThat(offenders).isEmpty();
        assertThat(MatrixIds.class.getDeclaredMethod(PARSE_METHOD, String.class)).isNotNull();
    }

    @Test
    void noMainCodeSplitsAUserIdOutsideMatrixIds() throws IOException {
        List<String> offenders = new ArrayList<>();
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            if (name.equals(PARSER_FILE)) {
                continue;
            }
            Set<String> allowed = SURGERY_ALLOWED.getOrDefault(name, Set.of());
            for (String line : codeLines(file)) {
                if (USER_ID_SURGERY.matcher(line).find() && !allowed.contains(line)) {
                    offenders.add(name + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    @Test
    void onlyTheResolverCallsTheLocalpartParser() throws IOException {
        List<String> offenders = new ArrayList<>();
        String resolverCode = null;
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            String code = String.join("\n", codeLines(file));
            if (name.equals(RESOLVER_FILE)) {
                resolverCode = code;
            } else if (!name.equals(PARSER_FILE) && code.contains(PARSE_METHOD + "(")) {
                offenders.add(name + " calls " + PARSE_METHOD);
            }
        }

        assertThat(offenders).isEmpty();
        assertThat(resolverCode).as(RESOLVER_FILE).contains("MatrixIds." + PARSE_METHOD + "(");
    }

    @Test
    void preferredUsernameComesOnlyFromTheResolverOrANewUsersChosenHandle() throws IOException {
        List<String> offenders = new ArrayList<>();
        int resolverSourced = 0;
        for (Path file : mainSources()) {
            String name = file.getFileName().toString();
            String code = String.join("\n", codeLines(file));
            Set<String> allowed = PREFERRED_USERNAME_ALLOWED.getOrDefault(name, Set.of());

            Matcher call = SET_PREFERRED_USERNAME.matcher(code);
            while (call.find()) {
                String argument = call.group(1).replaceAll("\\s+", "");
                if (!allowed.contains(argument)) {
                    offenders.add(name + ": setPreferredUsername(" + argument + ")");
                }
            }
            if (allowed.contains("preferredUsername")) {
                List<String> sources = assignedFrom(code, "preferredUsername");
                resolverSourced += sources.size();
                sources.stream()
                        .filter(rhs -> !rhs.startsWith(RESOLVE_CALL))
                        .forEach(rhs -> offenders.add(name + ": preferredUsername = " + rhs));
            }
            if (allowed.contains("localpart")) {
                assignedFrom(code, "localpart").stream()
                        .filter(rhs -> !rhs.startsWith(NEW_HANDLE_CALL))
                        .forEach(rhs -> offenders.add(name + ": localpart = " + rhs));
            }
        }

        assertThat(offenders).isEmpty();
        assertThat(resolverSourced).as("resolver-sourced preferredUsername assignments").isPositive();
    }

    /** Right-hand sides (whitespace removed) of every plain assignment to {@code variable}. */
    private static List<String> assignedFrom(String code, String variable) {
        Matcher assignment = Pattern.compile("\\b" + variable + "\\s*=(?!=)\\s*([^;]*);").matcher(code);
        List<String> sources = new ArrayList<>();
        while (assignment.find()) {
            sources.add(assignment.group(1).replaceAll("\\s+", ""));
        }
        return sources;
    }

    private static List<Path> mainSources() throws IOException {
        assertThat(MAIN_SOURCES).as("run from the identity-service project directory").isDirectory();
        try (Stream<Path> paths = Files.walk(MAIN_SOURCES)) {
            List<Path> files = paths.filter(path -> path.toString().endsWith(".java")).toList();
            assertThat(files).isNotEmpty();
            return files;
        }
    }

    /** Trimmed source lines with comment-only lines and trailing line comments removed. */
    private static List<String> codeLines(Path file) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String raw : Files.readAllLines(file)) {
            String line = raw.replaceAll("\\s//.*$", "").trim();
            if (line.isEmpty() || line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) {
                continue;
            }
            lines.add(line);
        }
        return lines;
    }
}
