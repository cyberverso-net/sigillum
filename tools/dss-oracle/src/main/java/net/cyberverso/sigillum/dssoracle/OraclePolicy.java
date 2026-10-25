package net.cyberverso.sigillum.dssoracle;

import java.util.Optional;

/**
 * A built-in validation policy of a validation mode, named with
 * {@code --policy} (ADR-0023). Without the option, the modes use
 * {@link #ALIGNED}. Any other value of the option names a policy file.
 */
public enum OraclePolicy {
    /**
     * The default policy of DSS with the deltas of ADR-0023, which the
     * comparisons with sigillum and the corpus predictions use.
     */
    ALIGNED("aligned", "aligned-" + AlignedPolicy.VERSION),
    /** The default policy of DSS, unchanged, for information only. */
    DEFAULT("default", "default");

    private final String commandName;
    private final String identifier;

    OraclePolicy(String commandName, String identifier) {
        this.commandName = commandName;
        this.identifier = identifier;
    }

    /**
     * Returns the value of {@code --policy} that selects the policy.
     *
     * @return the name on the command line
     */
    public String commandName() {
        return commandName;
    }

    /**
     * Returns the identifier written to {@code summary.json}, which names
     * the version of the aligned policy.
     *
     * @return the identifier, such as {@code aligned-1}
     */
    public String identifier() {
        return identifier;
    }

    /**
     * Finds the built-in policy that a value of {@code --policy} names.
     *
     * @param name the value, compared exactly
     * @return the policy, or empty when the value names none, and so a file
     */
    public static Optional<OraclePolicy> fromCommandName(String name) {
        for (OraclePolicy policy : values()) {
            if (policy.commandName.equals(name)) {
                return Optional.of(policy);
            }
        }
        return Optional.empty();
    }
}
