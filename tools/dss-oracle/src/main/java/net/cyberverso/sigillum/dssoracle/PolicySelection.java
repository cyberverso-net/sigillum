package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * The validation policy of a run, as {@code --policy} selects it
 * (ADR-0023): the aligned policy, the default policy of DSS, or a DSS
 * policy file. Every validation mode selects its policy here, so that the
 * modes treat the option alike.
 */
public final class PolicySelection {

    /** The kind of validation, which decides the default policy of DSS that applies. */
    public enum Kind {
        /** A certificate validation, whose default is {@link AlignedPolicy#CERTIFICATE_BASE}. */
        CERTIFICATE,
        /** A signature or timestamp validation, whose default is {@link AlignedPolicy#DOCUMENT_BASE}. */
        DOCUMENT
    }

    private final OraclePolicy named;
    private final OfflineSources.Input file;

    private PolicySelection(OraclePolicy named, OfflineSources.Input file) {
        this.named = named;
        this.file = file;
    }

    /**
     * Selects a built-in policy.
     *
     * @param policy the policy
     * @return the selection
     */
    public static PolicySelection named(OraclePolicy policy) {
        return new PolicySelection(policy, null);
    }

    /**
     * Selects the policy of a command line, reading the policy file if one
     * is named. Without {@code --policy}, it selects the aligned policy.
     *
     * @param arguments the command line
     * @return the selection
     * @throws IOException if the policy file is missing or cannot be read
     */
    public static PolicySelection of(Arguments arguments) throws IOException {
        PolicyOption option = arguments.policy().orElse(PolicyOption.named(OraclePolicy.ALIGNED));
        return option.named() != null
                ? named(option.named())
                : new PolicySelection(null, OfflineSources.Input.read("--policy", option.file()));
    }

    /**
     * Returns the member {@code policy} of {@code summary.json}: the
     * identifier of a built-in policy, or for a file an object with the file
     * as named on the command line and the SHA-256 digest of its content.
     *
     * @return a {@link String} or a {@link Map}
     */
    public Object summary() {
        if (named != null) {
            return named.identifier();
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("file", file.file().toString());
        summary.put("sha256", HexFormat.of().formatHex(sha256(file.content())));
        return summary;
    }

    /**
     * Runs a validation with the selected policy. A policy file is loaded
     * through the public policy API of DSS, which checks it against the
     * policy schema of DSS. When the validation fails with that file but
     * succeeds with the aligned policy, the failure belongs to the file;
     * when it fails with both, the first failure is thrown, with the second
     * suppressed.
     *
     * @param kind the kind of validation
     * @param validation the validation, given the policy
     * @param <R> the reports of the validation
     * @return the reports
     * @throws RejectedInputException if DSS cannot load or use the policy file
     */
    public <R> R validate(Kind kind, Function<ValidationPolicy, R> validation) throws RejectedInputException {
        if (named != null) {
            return validation.apply(builtIn(named, kind));
        }
        ValidationPolicy policy;
        try {
            policy = ValidationPolicyLoader.fromValidationPolicy(
                    new InMemoryDocument(file.content(), file.file().getFileName().toString())).create();
        } catch (RuntimeException e) {
            // DSS reports a policy it cannot read or that its schema refuses with an unchecked exception.
            throw new RejectedInputException("--policy", file.file(), e);
        }
        try {
            return validation.apply(policy);
        } catch (RuntimeException e) {
            // Every other input has been checked before the validation: if the aligned policy validates the same
            // inputs, the failure comes from the policy file. Otherwise the first failure stands.
            try {
                validation.apply(builtIn(OraclePolicy.ALIGNED, kind));
            } catch (RuntimeException again) {
                e.addSuppressed(again);
                throw e;
            }
            throw new RejectedInputException("--policy", file.file(), e);
        }
    }

    /** The built-in policy for a kind of validation. */
    private static ValidationPolicy builtIn(OraclePolicy policy, Kind kind) {
        return switch (policy) {
            case ALIGNED -> kind == Kind.CERTIFICATE ? AlignedPolicy.forCertificates() : AlignedPolicy.forDocuments();
            case DEFAULT -> kind == Kind.CERTIFICATE ? dssCertificateDefault()
                    : ValidationPolicyLoader.fromDefaultValidationPolicy().create();
        };
    }

    /** The default certificate validation policy of DSS, loaded as DSS loads it when no policy is given. */
    private static ValidationPolicy dssCertificateDefault() {
        try (InputStream in = ValidationPolicyFacade.class.getResourceAsStream(AlignedPolicy.CERTIFICATE_BASE)) {
            if (in == null) {
                throw new IllegalStateException("DSS ships no policy " + AlignedPolicy.CERTIFICATE_BASE);
            }
            return ValidationPolicyLoader.fromValidationPolicy(in).create();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read the policy " + AlignedPolicy.CERTIFICATE_BASE, e);
        }
    }

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The JVM has no SHA-256", e);
        }
    }
}
