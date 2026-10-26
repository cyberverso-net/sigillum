package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.format.SignStyle;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The parsed command line: {@code dss-oracle <mode> [options]}.
 *
 * @param mode the mode to run
 * @param validationTime the fixed validation or signing time, if given
 * @param trustAnchors trust anchor certificates
 * @param certificates certificates supplied offline; in validate-certificate,
 *        the first is the certificate to validate
 * @param crls CRLs supplied offline
 * @param ocspResponses OCSP responses supplied offline
 * @param out the output directory, if given
 * @param timestamp the timestamp token to validate, if given (validate-timestamp only)
 * @param data the data the timestamp covers, if given (validate-timestamp only)
 * @param digest the digest of the data the timestamp covers, in hexadecimal, if given
 *        (validate-timestamp only)
 * @param digestAlgorithm the name of the algorithm of {@code digest}, if given
 *        (validate-timestamp only)
 * @param policy the validation policy, a built-in one or a file, if given
 *        (validation modes only); the modes use {@link OraclePolicy#ALIGNED}
 *        without it
 * @param document the signed document to validate, if given (validate-document only)
 * @param detached the detached content of the signed document, if given
 *        (validate-document only)
 * @param timeout the time limit of the validation, in seconds, if given
 * @param sign the options of the sign mode, empty in the other modes
 */
public record Arguments(
        Mode mode,
        Optional<Instant> validationTime,
        List<Path> trustAnchors,
        List<Path> certificates,
        List<Path> crls,
        List<Path> ocspResponses,
        Optional<Path> out,
        Optional<Path> timestamp,
        Optional<Path> data,
        Optional<String> digest,
        Optional<String> digestAlgorithm,
        Optional<PolicyOption> policy,
        Optional<Path> document,
        Optional<Path> detached,
        Optional<Integer> timeout,
        SignArguments sign) {

    /** The largest time limit accepted, one day in seconds. */
    public static final int MAX_TIMEOUT_SECONDS = 86_400;

    /**
     * Parses the arguments that follow the program name.
     *
     * @param args the arguments
     * @return the parsed command line
     * @throws UsageException if the command line is not valid
     */
    public static Arguments parse(List<String> args) throws UsageException {
        if (args.isEmpty()) {
            throw new UsageException("No mode given.");
        }
        Mode mode = Arrays.stream(Mode.values())
                .filter(candidate -> candidate.commandName().equals(args.get(0)))
                .findFirst()
                .orElseThrow(() -> new UsageException("Unknown mode: " + args.get(0)));
        Instant validationTime = null;
        Path out = null;
        Path timestamp = null;
        Path data = null;
        String digest = null;
        String digestAlgorithm = null;
        PolicyOption policy = null;
        Path document = null;
        Path detached = null;
        Integer timeout = null;
        List<Path> trustAnchors = new ArrayList<>();
        List<Path> certificates = new ArrayList<>();
        List<Path> crls = new ArrayList<>();
        List<Path> ocspResponses = new ArrayList<>();
        SignArguments.Builder sign = new SignArguments.Builder();
        for (int i = 1; i < args.size(); i += 2) {
            String option = args.get(i);
            String value = valueOf(args, i);
            switch (option) {
                case "--validation-time" -> {
                    if (validationTime != null) {
                        throw new UsageException("--validation-time is given more than once.");
                    }
                    validationTime = rfc3339(option, value);
                }
                case "--out" -> {
                    if (out != null) {
                        throw new UsageException("--out is given more than once.");
                    }
                    out = Path.of(value);
                }
                case "--timestamp" ->
                        timestamp = Path.of(once(timestamp, option, mode, Mode.VALIDATE_TIMESTAMP, value));
                case "--data" -> data = Path.of(once(data, option, mode, Mode.VALIDATE_TIMESTAMP, value));
                case "--digest" -> digest = once(digest, option, mode, Mode.VALIDATE_TIMESTAMP, value);
                case "--digest-algorithm" ->
                        digestAlgorithm = once(digestAlgorithm, option, mode, Mode.VALIDATE_TIMESTAMP, value);
                case "--document" -> {
                    // The document to sign in the sign mode, the signed document in validate-document.
                    if (mode == Mode.SIGN) {
                        sign.add(option, value);
                    } else {
                        document = Path.of(once(document, option, mode, Mode.VALIDATE_DOCUMENT, value));
                    }
                }
                case "--detached" -> detached = Path.of(once(detached, option, mode, Mode.VALIDATE_DOCUMENT, value));
                case "--policy" -> {
                    if (mode == Mode.SIGN) {
                        throw new UsageException("--policy is valid only in the validation modes.");
                    }
                    if (policy != null) {
                        throw new UsageException("--policy is given more than once.");
                    }
                    policy = PolicyOption.parse(value);
                }
                case "--timeout" -> {
                    if (mode == Mode.SIGN) {
                        throw new UsageException("--timeout is valid only in the validation modes.");
                    }
                    if (timeout != null) {
                        throw new UsageException("--timeout is given more than once.");
                    }
                    timeout = seconds(value);
                }
                case "--trust-anchor" -> trustAnchors.add(Path.of(value));
                case "--certificate" -> certificates.add(Path.of(value));
                case "--crl" -> crls.add(Path.of(value));
                case "--ocsp" -> ocspResponses.add(Path.of(value));
                default -> {
                    if (!SignArguments.OPTIONS.contains(option)) {
                        throw new UsageException("Unknown option: " + option);
                    }
                    if (mode != Mode.SIGN) {
                        throw new UsageException(option + " is valid only in the mode " + Mode.SIGN.commandName()
                                + ".");
                    }
                    sign.add(option, value);
                }
            }
        }
        return new Arguments(mode, Optional.ofNullable(validationTime), List.copyOf(trustAnchors),
                List.copyOf(certificates), List.copyOf(crls), List.copyOf(ocspResponses), Optional.ofNullable(out),
                Optional.ofNullable(timestamp), Optional.ofNullable(data), Optional.ofNullable(digest),
                Optional.ofNullable(digestAlgorithm), Optional.ofNullable(policy), Optional.ofNullable(document),
                Optional.ofNullable(detached), Optional.ofNullable(timeout), sign.build());
    }

    /**
     * Checks an option of one mode that may be given once.
     *
     * @param valid the mode in which the option is valid
     * @return the value of the option
     */
    private static String once(Object previous, String option, Mode mode, Mode valid, String value)
            throws UsageException {
        if (mode != valid) {
            throw new UsageException(option + " is valid only in the mode " + valid.commandName() + ".");
        }
        if (previous != null) {
            throw new UsageException(option + " is given more than once.");
        }
        return value;
    }

    private static int seconds(String value) throws UsageException {
        if (!value.matches("[0-9]{1,9}")) {
            throw new UsageException("--timeout is not a whole number of seconds: " + value);
        }
        int seconds = Integer.parseInt(value);
        if (seconds < 1 || seconds > MAX_TIMEOUT_SECONDS) {
            throw new UsageException("--timeout must be from 1 to " + MAX_TIMEOUT_SECONDS + " seconds: " + value);
        }
        return seconds;
    }

    private static String valueOf(List<String> args, int optionIndex) throws UsageException {
        String option = args.get(optionIndex);
        if (!option.startsWith("--")) {
            throw new UsageException("Unexpected argument: " + option);
        }
        if (optionIndex + 1 >= args.size() || args.get(optionIndex + 1).startsWith("--")) {
            throw new UsageException(option + " needs a value.");
        }
        String value = args.get(optionIndex + 1);
        if (value.isBlank()) {
            throw new UsageException(option + " needs a value that is not blank.");
        }
        return value;
    }

    /** RFC 3339, section 5.6: full-date "T" full-time, with seconds and a numeric or "Z" offset. */
    private static final DateTimeFormatter RFC_3339 = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendValue(ChronoField.YEAR, 4, 4, SignStyle.NOT_NEGATIVE)
            .appendPattern("-MM-dd'T'HH:mm:ss")
            .optionalStart()
            .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, true)
            .optionalEnd()
            .appendOffset("+HH:MM", "Z")
            .toFormatter()
            .withResolverStyle(ResolverStyle.STRICT);

    /**
     * Parses the value of a time option.
     *
     * @param option the option, for the error message
     * @param value the value
     * @return the time
     * @throws UsageException if the value is not an RFC 3339 time with an offset, or is a leap second
     */
    static Instant rfc3339(String option, String value) throws UsageException {
        if (value.length() >= 19 && value.substring(17, 19).equals("60")) {
            throw new UsageException(option + ": leap seconds are not supported: " + value);
        }
        try {
            return OffsetDateTime.parse(value, RFC_3339).toInstant();
        } catch (DateTimeParseException e) {
            throw new UsageException(option + " is not an RFC 3339 time with an offset: " + value);
        }
    }
}
