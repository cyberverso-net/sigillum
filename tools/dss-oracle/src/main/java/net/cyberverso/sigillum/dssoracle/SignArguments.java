package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The options of the sign mode, as given on the command line. The options
 * {@code --certificate}, {@code --trust-anchor}, {@code --crl},
 * {@code --ocsp}, {@code --validation-time} and {@code --out} are common to
 * every mode and stay in {@link Arguments}. {@link Sign} checks which
 * options a run needs.
 *
 * @param format the signature format, {@code cades}, {@code pades} or {@code jades}
 * @param level the baseline level, {@code B-B}, {@code B-T} or {@code B-LT}
 * @param key the PKCS#8 private key of the signer
 * @param chain the certificates above the signing certificate
 * @param signingTime the signing time
 * @param document the document to sign
 * @param packaging {@code enveloping} or {@code detached}
 * @param serialisation the JWS serialisation of JAdES: {@code compact}, {@code flattened} or {@code general}
 * @param signatureAlgorithm the DSS name of the signature algorithm
 * @param tsaProgram the {@code sigillum-testpki} program that issues timestamp tokens
 * @param tsaKey the private key of the timestamping authority
 * @param tsaCertificate the certificate of the timestamping authority
 * @param tsaChain the certificates above the certificate of the timestamping authority
 * @param timestampTime the time of the signature timestamp
 */
public record SignArguments(
        Optional<String> format,
        Optional<String> level,
        Optional<Path> key,
        List<Path> chain,
        Optional<Instant> signingTime,
        Optional<Path> document,
        Optional<String> packaging,
        Optional<String> serialisation,
        Optional<String> signatureAlgorithm,
        Optional<Path> tsaProgram,
        Optional<Path> tsaKey,
        Optional<Path> tsaCertificate,
        List<Path> tsaChain,
        Optional<Instant> timestampTime) {

    /** The options that only the sign mode accepts. */
    static final Set<String> OPTIONS = Set.of("--format", "--level", "--key", "--chain", "--signing-time",
            "--document", "--packaging", "--serialisation", "--signature-algorithm", "--tsa-program", "--tsa-key",
            "--tsa-cert", "--tsa-chain", "--timestamp-time");

    /** Collects the options of the sign mode while the command line is parsed. */
    static final class Builder {
        private String format;
        private String level;
        private Path key;
        private final List<Path> chain = new ArrayList<>();
        private Instant signingTime;
        private Path document;
        private String packaging;
        private String serialisation;
        private String signatureAlgorithm;
        private Path tsaProgram;
        private Path tsaKey;
        private Path tsaCertificate;
        private final List<Path> tsaChain = new ArrayList<>();
        private Instant timestampTime;

        /**
         * Records an option of {@link #OPTIONS}.
         *
         * @param option the option
         * @param value its value
         * @throws UsageException if an option that may be given once is repeated, or a time is not valid
         */
        void add(String option, String value) throws UsageException {
            switch (option) {
                case "--format" -> format = once(format, option, value);
                case "--level" -> level = once(level, option, value);
                case "--key" -> key = Path.of(once(key, option, value));
                case "--chain" -> chain.add(Path.of(value));
                case "--signing-time" -> signingTime = time(once(signingTime, option, value), option);
                case "--document" -> document = Path.of(once(document, option, value));
                case "--packaging" -> packaging = once(packaging, option, value);
                case "--serialisation" -> serialisation = once(serialisation, option, value);
                case "--signature-algorithm" -> signatureAlgorithm = once(signatureAlgorithm, option, value);
                case "--tsa-program" -> tsaProgram = Path.of(once(tsaProgram, option, value));
                case "--tsa-key" -> tsaKey = Path.of(once(tsaKey, option, value));
                case "--tsa-cert" -> tsaCertificate = Path.of(once(tsaCertificate, option, value));
                case "--tsa-chain" -> tsaChain.add(Path.of(value));
                case "--timestamp-time" -> timestampTime = time(once(timestampTime, option, value), option);
                default -> throw new UsageException("Unknown option: " + option);
            }
        }

        SignArguments build() {
            return new SignArguments(Optional.ofNullable(format), Optional.ofNullable(level),
                    Optional.ofNullable(key), List.copyOf(chain), Optional.ofNullable(signingTime),
                    Optional.ofNullable(document), Optional.ofNullable(packaging),
                    Optional.ofNullable(serialisation), Optional.ofNullable(signatureAlgorithm),
                    Optional.ofNullable(tsaProgram), Optional.ofNullable(tsaKey),
                    Optional.ofNullable(tsaCertificate), List.copyOf(tsaChain), Optional.ofNullable(timestampTime));
        }

        private static String once(Object previous, String option, String value) throws UsageException {
            if (previous != null) {
                throw new UsageException(option + " is given more than once.");
            }
            return value;
        }

        /**
         * Parses a time in whole seconds. CMS signing times and the genTime
         * that {@code sigillum-testpki tsa} accepts have no fraction of a
         * second.
         */
        private static Instant time(String value, String option) throws UsageException {
            Instant time = Arguments.rfc3339(option, value);
            if (time.getNano() != 0) {
                throw new UsageException(option + " must be a whole number of seconds: " + value);
            }
            return time;
        }
    }
}
