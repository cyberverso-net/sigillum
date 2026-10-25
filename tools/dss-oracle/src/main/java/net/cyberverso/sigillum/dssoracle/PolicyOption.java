package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;
import java.util.Objects;

/**
 * The value of {@code --policy}: a built-in policy, by name, or a DSS
 * policy file (ADR-0023). Exactly one of the two is set.
 *
 * @param named the built-in policy, or {@code null}
 * @param file the policy file, or {@code null}
 */
public record PolicyOption(OraclePolicy named, Path file) {

    /**
     * Checks that exactly one of the two is set.
     *
     * @param named the built-in policy, or {@code null}
     * @param file the policy file, or {@code null}
     */
    public PolicyOption {
        if ((named == null) == (file == null)) {
            throw new IllegalArgumentException("A policy option names a built-in policy or a file.");
        }
    }

    /**
     * A built-in policy.
     *
     * @param policy the policy
     * @return the option
     */
    public static PolicyOption named(OraclePolicy policy) {
        return new PolicyOption(Objects.requireNonNull(policy), null);
    }

    /**
     * A policy file.
     *
     * @param file the file
     * @return the option
     */
    public static PolicyOption file(Path file) {
        return new PolicyOption(null, Objects.requireNonNull(file));
    }

    /**
     * Parses a value of {@code --policy}: the name of a built-in policy, or
     * otherwise the path of a policy file. A file named like a built-in
     * policy is given with a path, such as {@code ./aligned}.
     *
     * @param value the value
     * @return the option
     */
    public static PolicyOption parse(String value) {
        return OraclePolicy.fromCommandName(value).map(PolicyOption::named)
                .orElseGet(() -> file(Path.of(value)));
    }
}
