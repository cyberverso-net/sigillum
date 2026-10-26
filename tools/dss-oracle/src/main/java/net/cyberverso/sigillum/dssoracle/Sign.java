package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.OCSPFirstRevocationDataLoadingStrategy;
import eu.europa.esig.dss.spi.validation.RevocationDataLoadingStrategy;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.RevocationDataVerifierFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;

/**
 * The mode {@code sign}: creates a CAdES, PAdES or JAdES baseline signature
 * with DSS, with a test key, a fixed signing time and offline sources only
 * (ADR-0013). At B-T and B-LT, the signature timestamp comes from
 * {@code sigillum-testpki tsa} at a configured time ({@link TestPkiTspSource}).
 * At B-LT, DSS collects the validation data from the CRLs and OCSP
 * responses supplied, at the time given by {@code --validation-time}, and
 * embeds them.
 *
 * <p>Every input is a file of the project. An input that DSS cannot use
 * fails the run with exit code 1, since no signature can be produced from
 * it; the mode has no {@code rejected} result. Every signature is
 * deterministic, so that two runs with the same inputs give the same bytes.
 */
public final class Sign implements Main.ModeRunner {

    /** The environment variable that locates {@code sigillum-testpki} when {@code --tsa-program} is not given. */
    public static final String PROGRAM_VARIABLE = "SIGILLUM_TESTPKI";

    /** The digest algorithm of the signature timestamp, which {@code sigillum-testpki tsa} supports. */
    static final DigestAlgorithm TIMESTAMP_DIGEST = DigestAlgorithm.SHA256;

    private final Map<String, String> environment;

    /**
     * Creates the mode.
     *
     * @param environment the environment of the process, where {@value #PROGRAM_VARIABLE} may be set
     */
    public Sign(Map<String, String> environment) {
        this.environment = Map.copyOf(environment);
    }

    /** The signature formats. */
    enum Format {
        CADES, PADES, JADES
    }

    /** The baseline levels of ETSI EN 319 122-1, EN 319 142-1 and TS 119 182-1 that the mode creates. */
    enum Level {
        B_B("B-B"), B_T("B-T"), B_LT("B-LT");

        private final String name;

        Level(String name) {
            this.name = name;
        }

        boolean timestamped() {
            return this != B_B;
        }
    }

    /** The JWS serialisations of RFC 7515, section 7. */
    enum Serialisation {
        COMPACT(JWSSerializationType.COMPACT_SERIALIZATION),
        FLATTENED(JWSSerializationType.FLATTENED_JSON_SERIALIZATION),
        GENERAL(JWSSerializationType.JSON_SERIALIZATION);

        private final JWSSerializationType type;

        Serialisation(JWSSerializationType type) {
            this.type = type;
        }
    }

    /** The timestamping authority of a run at B-T or B-LT. */
    private record Tsa(Path program, Path key, Path certificate, List<Path> chain, Instant time) {
    }

    /** The checked command line of this mode. */
    private record Options(Format format, Level level, Path key, Path certificate, List<Path> chain,
            Instant signingTime, Path document, SignaturePackaging packaging, Serialisation serialisation,
            Optional<SignatureAlgorithm> algorithm, Tsa tsa, Instant validationTime, Path out) {
    }

    @Override
    public int run(Arguments arguments, PrintStream out, PrintStream err) throws Exception {
        Options options = check(arguments);
        if (Files.exists(options.out(), LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("--out " + options.out() + ": the file exists");
        }
        DSSSecurityProvider.initSystemProviders();

        // Read every file first: a missing file fails the run, whatever else is wrong.
        OfflineSources.Input key = OfflineSources.Input.read("--key", options.key());
        OfflineSources.Input document = OfflineSources.Input.read("--document", options.document());
        List<OfflineSources.Input> chain = new ArrayList<>();
        for (Path file : options.chain()) {
            chain.add(OfflineSources.Input.read("--chain", file));
        }
        List<OfflineSources.Input> tsaChain = new ArrayList<>();
        if (options.tsa() != null) {
            OfflineSources.Input.read("--tsa-key", options.tsa().key());
            OfflineSources.Input.read("--tsa-cert", options.tsa().certificate());
            for (Path file : options.tsa().chain()) {
                tsaChain.add(OfflineSources.Input.read("--tsa-chain", file));
            }
        }
        OfflineSources sources = OfflineSources.read(arguments);
        if (document.content().length == 0) {
            // A JWS with an empty payload reads as a detached signature (RFC 7515, appendix F).
            throw new IOException("--document " + document.file() + ": the document is empty");
        }

        CertificateToken signingCertificate = usable(() -> sources.suppliedCertificate(0));
        List<CertificateToken> chainCertificates = certificates(chain);
        List<CertificateToken> tsaCertificates = certificates(tsaChain);
        List<CertificateToken> others = new ArrayList<>(chainCertificates);
        others.addAll(tsaCertificates);
        CertificateVerifier verifier = usable(() -> sources.certificateVerifier(others));
        CommonCertificateSource adjunct = new CommonCertificateSource();
        others.forEach(adjunct::addCertificate);
        verifier.addAdjunctCertSources(adjunct);
        if (options.validationTime() != null) {
            configureRevocation(verifier, options.validationTime());
        }

        SigningKey signingKey;
        try {
            signingKey = SigningKey.read(key.content());
        } catch (IllegalArgumentException e) {
            throw new IOException("--key " + key.file() + ": " + e.getMessage(), e);
        }
        SignatureAlgorithm algorithm = algorithm(options, signingKey, key);
        checkKeyMatches(signingKey, algorithm, signingCertificate, key);

        TSPSource tspSource = options.tsa() == null ? null : new TestPkiTspSource(options.tsa().program(),
                options.tsa().key(), options.tsa().certificate(), options.tsa().time());
        Signed signed = new Signed(document.document(), signingKey, algorithm, signingCertificate,
                chainCertificates, options);
        DSSDocument result;
        try {
            result = switch (options.format()) {
                case CADES -> signed.cades(verifier, tspSource);
                case PADES -> signed.pades(verifier, tspSource);
                case JADES -> signed.jades(verifier, tspSource);
            };
        } catch (DSSException | UncheckedIOException | IllegalArgumentException | IllegalStateException e) {
            throw new IOException("DSS cannot create the signature: " + e.getMessage(), e);
        }
        byte[] bytes;
        try (var in = result.openStream()) {
            bytes = in.readAllBytes();
        }
        checkIntact(bytes, document.document(), options);
        Files.write(options.out(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return ExitCodes.SUCCESS;
    }

    /**
     * Validates the signature with DSS, offline and without revocation data,
     * and fails unless DSS finds exactly one signature whose value and
     * references are intact, with an intact signature timestamp at B-T and
     * B-LT. The mode thus never writes a signature that does not verify,
     * whatever input DSS accepted: a certificate whose names DSS cannot
     * decode, for example, or a token whose signature does not verify.
     */
    private static void checkIntact(byte[] signed, DSSDocument document, Options options) throws IOException {
        String problem;
        try {
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signed));
            CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
            verifier.setAIASource(null);
            validator.setCertificateVerifier(verifier);
            validator.setValidationTime(Date.from(options.signingTime()));
            if (options.packaging() == SignaturePackaging.DETACHED) {
                validator.setDetachedContents(List.of(document));
            }
            List<SignatureWrapper> signatures = validator.validateDocument().getDiagnosticData().getSignatures();
            problem = intactness(signatures, options.level().timestamped());
        } catch (RuntimeException e) {
            // Whatever DSS or Bouncy Castle throws, the signature is not written.
            problem = "DSS cannot validate it: " + e;
        }
        if (problem != null) {
            throw new IOException("DSS created a signature that does not verify: " + problem);
        }
    }

    private static String intactness(List<SignatureWrapper> signatures, boolean timestamped) {
        if (signatures.size() != 1) {
            return signatures.size() + " signatures found";
        }
        SignatureWrapper signature = signatures.get(0);
        if (!signature.isSignatureIntact() || !signature.isSignatureValid()) {
            return "the signature value does not verify";
        }
        if (signature.getDigestMatchers().isEmpty() || !signature.getDigestMatchers().stream()
                .allMatch(matcher -> matcher.isDataFound() && matcher.isDataIntact())) {
            return "the signed data do not match";
        }
        if (timestamped) {
            List<TimestampWrapper> timestamps = signature.getTimestampList();
            if (timestamps.isEmpty() || !timestamps.stream().allMatch(timestamp -> timestamp.isSignatureIntact()
                    && timestamp.isSignatureValid() && timestamp.isMessageImprintDataFound()
                    && timestamp.isMessageImprintDataIntact())) {
                return "the signature timestamp does not verify";
            }
        }
        return null;
    }

    /** A step that DSS may refuse because of an input file. */
    @FunctionalInterface
    private interface Use<T> {
        T get() throws RejectedInputException;
    }

    /** Runs a step, and turns a file that DSS cannot use into a failure of the run. */
    private static <T> T usable(Use<T> step) throws IOException {
        try {
            return step.get();
        } catch (RejectedInputException e) {
            throw new IOException(e.option() + " " + e.file() + ": " + e.getMessage(), e);
        }
    }

    private static List<CertificateToken> certificates(List<OfflineSources.Input> inputs) throws IOException {
        List<CertificateToken> certificates = new ArrayList<>();
        for (OfflineSources.Input input : inputs) {
            certificates.add(usable(input::certificate));
        }
        return certificates;
    }

    /**
     * Configures how DSS selects the revocation data that it embeds at B-LT.
     * This is the one place where the revocation checks of signing are set.
     *
     * <p>The strategy is that of DSS, OCSP first, with the revocation data
     * checked at {@code controlTime} rather than at the time of the clock.
     * DSS accepts a CRL or OCSP response under the cryptographic constraints
     * of the aligned policy (ADR-0023), which authorises EdDSA, at that same
     * time. The revocation fallback of DSS stays disabled, so a CRL or OCSP
     * response that fails the checks, for example one whose signature does
     * not verify, is never embedded; the run fails when no accepted
     * revocation data remains for a certificate that needs it. The offline
     * sources of DSS take the CRLs and OCSP responses in the order given on
     * the command line.
     */
    private static void configureRevocation(CertificateVerifier verifier, Instant controlTime) {
        Date time = Date.from(controlTime);
        verifier.setRevocationDataVerifier(new RevocationDataVerifierFactory(AlignedPolicy.forDocuments())
                .setValidationTime(time).create());
        verifier.setRevocationDataLoadingStrategyFactory(() -> fixedTime(time));
        verifier.setRevocationFallback(false);
    }

    /** The revocation strategy of DSS, OCSP first, checking revocation data at a fixed time rather than the clock. */
    private static RevocationDataLoadingStrategy fixedTime(Date controlTime) {
        return new OCSPFirstRevocationDataLoadingStrategy() {
            @Override
            protected Date getControlTime() {
                return new Date(controlTime.getTime());
            }
        };
    }

    private static SignatureAlgorithm algorithm(Options options, SigningKey key, OfflineSources.Input input)
            throws UsageException, IOException {
        SignatureAlgorithm algorithm;
        try {
            algorithm = options.algorithm().orElseGet(key::defaultAlgorithm);
        } catch (IllegalArgumentException e) {
            throw new IOException("--key " + input.file() + ": " + e.getMessage(), e);
        }
        if (!key.fits(algorithm)) {
            throw new UsageException("--signature-algorithm " + algorithm.name()
                    + " does not fit the key " + input.file() + ".");
        }
        return algorithm;
    }

    /** Signs a fixed message and verifies it with the key of the certificate. */
    private static void checkKeyMatches(SigningKey key, SignatureAlgorithm algorithm, CertificateToken certificate,
            OfflineSources.Input input) throws IOException {
        byte[] probe = "sigillum dss-oracle key check".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        boolean matches;
        try {
            SignatureValue value = key.sign(algorithm, probe);
            matches = SigningKey.verify(algorithm, certificate.getPublicKey(), probe, value.getValue());
        } catch (GeneralSecurityException | RuntimeException e) {
            matches = false;
        }
        if (!matches) {
            throw new IOException("--key " + input.file() + " does not match the key of --certificate with "
                    + algorithm.name());
        }
    }

    /**
     * Checks the options of the mode.
     *
     * @throws UsageException if an option is missing, not valid, or does not apply
     */
    private Options check(Arguments arguments) throws UsageException {
        SignArguments sign = arguments.sign();
        Format format = choice(sign.format(), "--format", Format.class, "cades, pades or jades");
        Level level = level(sign.level());
        Path key = sign.key().orElseThrow(() -> new UsageException("--key is required."));
        if (arguments.certificates().size() != 1) {
            throw new UsageException("--certificate is required once: the signing certificate.");
        }
        Instant signingTime = sign.signingTime().orElseThrow(() -> new UsageException("--signing-time is required."));
        Path document = sign.document().orElseThrow(() -> new UsageException("--document is required."));
        Path out = arguments.out().orElseThrow(() -> new UsageException("--out is required."));

        SignaturePackaging packaging = SignaturePackaging.ENVELOPING;
        if (sign.packaging().isPresent()) {
            if (format == Format.PADES) {
                throw new UsageException("--packaging does not apply to PAdES, which is always enveloped.");
            }
            packaging = switch (sign.packaging().get()) {
                case "enveloping" -> SignaturePackaging.ENVELOPING;
                case "detached" -> SignaturePackaging.DETACHED;
                default -> throw new UsageException("--packaging must be enveloping or detached: "
                        + sign.packaging().get());
            };
        }
        Serialisation serialisation = null;
        if (format == Format.JADES) {
            serialisation = choice(sign.serialisation(), "--serialisation", Serialisation.class,
                    "compact, flattened or general");
            if (serialisation == Serialisation.COMPACT && level.timestamped()) {
                // RFC 7515, section 7.1: the compact serialisation has no unprotected header for etsiU.
                throw new UsageException("--serialisation compact allows B-B only: it has no unprotected header.");
            }
        } else if (sign.serialisation().isPresent()) {
            throw new UsageException("--serialisation applies to JAdES only.");
        }
        Optional<SignatureAlgorithm> algorithm = Optional.empty();
        if (sign.signatureAlgorithm().isPresent()) {
            try {
                algorithm = Optional.of(SignatureAlgorithm.valueOf(sign.signatureAlgorithm().get()));
            } catch (IllegalArgumentException e) {
                throw new UsageException("--signature-algorithm is not a DSS signature algorithm: "
                        + sign.signatureAlgorithm().get());
            }
        }

        Tsa tsa = null;
        if (level.timestamped()) {
            String source = "--tsa-program";
            Path program = sign.tsaProgram().orElse(null);
            if (program == null) {
                String value = environment.get(PROGRAM_VARIABLE);
                program = value == null || value.isBlank() ? null : Path.of(value);
                source = "The environment variable " + PROGRAM_VARIABLE;
            }
            if (program == null) {
                throw new UsageException("--tsa-program or the environment variable " + PROGRAM_VARIABLE
                        + " is required at " + level.name + ".");
            }
            // A bare name would be looked up on the PATH; the program is named by a path instead.
            if (!program.isAbsolute() && program.getNameCount() < 2) {
                throw new UsageException(source + " must be a path to sigillum-testpki, such as ./"
                        + program + ", not a name looked up on the PATH: " + program);
            }
            if (level != Level.B_LT && !sign.tsaChain().isEmpty()) {
                throw new UsageException("--tsa-chain applies to B-LT only.");
            }
            tsa = new Tsa(program,
                    sign.tsaKey().orElseThrow(() -> new UsageException("--tsa-key is required at " + level.name
                            + ".")),
                    sign.tsaCertificate().orElseThrow(() -> new UsageException("--tsa-cert is required at "
                            + level.name + ".")),
                    sign.tsaChain(),
                    sign.timestampTime().orElseThrow(() -> new UsageException("--timestamp-time is required at "
                            + level.name + ".")));
        } else {
            // In the order of the usage text, so that the option reported does not depend on hashing.
            refuseGiven(List.of(
                    Map.entry("--tsa-program", sign.tsaProgram().isPresent()),
                    Map.entry("--tsa-key", sign.tsaKey().isPresent()),
                    Map.entry("--tsa-cert", sign.tsaCertificate().isPresent()),
                    Map.entry("--tsa-chain", !sign.tsaChain().isEmpty()),
                    Map.entry("--timestamp-time", sign.timestampTime().isPresent())), "B-T and B-LT");
        }

        Instant validationTime = null;
        if (level == Level.B_LT) {
            validationTime = arguments.validationTime().orElseThrow(() -> new UsageException(
                    "--validation-time is required at B-LT: the time at which DSS checks the validation data."));
            if (arguments.trustAnchors().isEmpty()) {
                throw new UsageException("--trust-anchor is required at B-LT.");
            }
        } else {
            refuseGiven(List.of(
                    Map.entry("--validation-time", arguments.validationTime().isPresent()),
                    Map.entry("--trust-anchor", !arguments.trustAnchors().isEmpty()),
                    Map.entry("--crl", !arguments.crls().isEmpty()),
                    Map.entry("--ocsp", !arguments.ocspResponses().isEmpty())), "B-LT");
        }
        return new Options(format, level, key, arguments.certificates().get(0), sign.chain(), signingTime,
                document, packaging, serialisation, algorithm, tsa, validationTime, out);
    }

    /** Refuses the first option of the list that is given, as applying to {@code levels} only. */
    private static void refuseGiven(List<Map.Entry<String, Boolean>> options, String levels) throws UsageException {
        for (Map.Entry<String, Boolean> option : options) {
            if (option.getValue()) {
                throw new UsageException(option.getKey() + " applies to " + levels + " only.");
            }
        }
    }

    private static Level level(Optional<String> value) throws UsageException {
        String name = value.orElseThrow(() -> new UsageException("--level is required."));
        for (Level candidate : Level.values()) {
            if (candidate.name.equals(name)) {
                return candidate;
            }
        }
        throw new UsageException("--level must be B-B, B-T or B-LT: " + name);
    }

    private static <E extends Enum<E>> E choice(Optional<String> value, String option, Class<E> type,
            String allowed) throws UsageException {
        String name = value.orElseThrow(() -> new UsageException(option + " is required."));
        for (E candidate : type.getEnumConstants()) {
            if (candidate.name().toLowerCase(Locale.ROOT).equals(name)) {
                return candidate;
            }
        }
        throw new UsageException(option + " must be " + allowed + ": " + name);
    }

    /** One signature to create, with the parameters common to the three formats. */
    private record Signed(DSSDocument document, SigningKey key, SignatureAlgorithm algorithm,
            CertificateToken certificate, List<CertificateToken> chain, Options options) {

        private void common(AbstractSignatureParameters<? extends TimestampParameters> parameters, SignatureLevel b, SignatureLevel t,
                SignatureLevel lt) {
            parameters.setSignatureLevel(switch (options.level()) {
                case B_B -> b;
                case B_T -> t;
                case B_LT -> lt;
            });
            parameters.setSigningCertificate(certificate);
            parameters.setCertificateChain(chain);
            parameters.setEncryptionAlgorithm(algorithm.getEncryptionAlgorithm());
            parameters.setDigestAlgorithm(algorithm.getDigestAlgorithm());
            parameters.bLevel().setSigningDate(Date.from(options.signingTime()));
            parameters.getSignatureTimestampParameters().setDigestAlgorithm(TIMESTAMP_DIGEST);
        }

        private <P extends AbstractSignatureParameters<?>> DSSDocument sign(DocumentSignatureService<P, ?> service,
                P parameters) {
            ToBeSigned data = service.getDataToSign(document, parameters);
            SignatureValue value;
            try {
                value = key.sign(parameters.getSignatureAlgorithm(), data.getBytes());
            } catch (GeneralSecurityException e) {
                throw new DSSException("the signature cannot be computed: " + e.getMessage(), e);
            }
            return service.signDocument(document, parameters, value);
        }

        DSSDocument cades(CertificateVerifier verifier, TSPSource tspSource) {
            CAdESService service = new CAdESService(verifier);
            service.setTspSource(tspSource);
            CAdESSignatureParameters parameters = new CAdESSignatureParameters();
            common(parameters, SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                    SignatureLevel.CAdES_BASELINE_LT);
            parameters.setSignaturePackaging(options.packaging());
            return sign(service, parameters);
        }

        DSSDocument pades(CertificateVerifier verifier, TSPSource tspSource) {
            PAdESService service = new PAdESService(verifier);
            service.setTspSource(tspSource);
            // The revision of the document security store at B-LT is seeded from the time of the
            // validation data, the signature revision from the signature parameters by DSS.
            Instant seed = options.validationTime() == null ? options.signingTime() : options.validationTime();
            service.setPdfObjFactory(new FixedIdPdfObjFactory(seed.toEpochMilli()));
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            common(parameters, SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T,
                    SignatureLevel.PAdES_BASELINE_LT);
            // The signing time of the signature dictionary (ISO 32000-1:2008, clause 12.8.1, M) in UTC,
            // whatever the time zone of the machine.
            parameters.setSigningTimeZone(TimeZone.getTimeZone("UTC"));
            return sign(service, parameters);
        }

        DSSDocument jades(CertificateVerifier verifier, TSPSource tspSource) {
            JAdESService service = new JAdESService(verifier);
            service.setTspSource(tspSource);
            JAdESSignatureParameters parameters = new JAdESSignatureParameters();
            common(parameters, SignatureLevel.JAdES_BASELINE_B, SignatureLevel.JAdES_BASELINE_T,
                    SignatureLevel.JAdES_BASELINE_LT);
            parameters.setSignaturePackaging(options.packaging());
            parameters.setJwsSerializationType(options.serialisation().type);
            // Implementing Regulation (EU) 2026/248, Annex I, adapts ETSI TS 119 182-1 V1.2.1, clause 5.1.8:
            // x5c is always present, here in the protected header.
            parameters.setIncludeCertificateChain(true);
            parameters.setX5CHeaderPlacement(JAdESSignatureParameters.X5CHeaderPlacement.protectedHeader);
            // ADR-0018: the payload is always base64url-encoded, and unsigned properties too (scope.md).
            parameters.setBase64UrlEncodedPayload(true);
            parameters.setBase64UrlEncodedEtsiUComponents(true);
            if (options.packaging() == SignaturePackaging.DETACHED) {
                // ADR-0018: detached signatures use ObjectIdByURIHash (TS 119 182-1 V1.2.1, clause 5.2.8.3.3).
                parameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
                parameters.setDetachedContents(List.of(document));
            }
            return sign(service, parameters);
        }
    }
}
