package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.tsp.TSPException;

/**
 * The mode {@code validate-timestamp}: validates a standalone RFC 3161
 * timestamp token with DSS at a fixed time, with offline sources only, and
 * checks its message imprint against data or a digest when one is given.
 */
public final class ValidateTimestamp implements Main.ModeRunner {

    /** Creates the mode. */
    public ValidateTimestamp() {
    }

    /** The checked command line of this mode. */
    private record Options(Path timestamp, Instant validationTime, Path out, DigestAlgorithm digestAlgorithm,
            byte[] digest) {
    }

    @Override
    public int run(Arguments arguments, PrintStream out, PrintStream err) throws Exception {
        Options options = check(arguments);
        PolicySelection policy = PolicySelection.of(arguments);
        ValidationOutput output = ValidationOutput.check(options.out(), Mode.VALIDATE_TIMESTAMP,
                options.validationTime(), policy);

        // Read every file first: a missing file is a failure of the tool, whatever else is wrong.
        OfflineSources.Input token = OfflineSources.Input.read("--timestamp", options.timestamp());
        OfflineSources.Input data = arguments.data().isPresent()
                ? OfflineSources.Input.read("--data", arguments.data().get())
                : null;
        OfflineSources sources = OfflineSources.read(arguments);

        // The validation runs within limits of heap, stack and time; exceeding one is a recorded result.
        ResourceLimits.run(ResourceLimits.Limits.of(arguments), output, () -> {
            try {
                TimestampToken parsed = parse(token, data != null);
                if (options.digestAlgorithm() != null
                        && parsed.getMessageImprint().getAlgorithm() != options.digestAlgorithm()) {
                    throw new UsageException("--digest-algorithm " + options.digestAlgorithm().getName()
                            + " differs from the algorithm of the message imprint of the token, "
                            + parsed.getMessageImprint().getAlgorithm().getName() + ".");
                }
                CertificateVerifier verifier = sources.certificateVerifier(certificates(parsed));
                List<CertificateToken> candidates = new ArrayList<>(certificates(parsed));
                candidates.addAll(verifier.getTrustedCertSources().getCertificates());
                candidates.addAll(verifier.getAdjunctCertSources().getCertificates());
                checkSigningCertificateReferences(token, parsed, candidates);
                checkCertificateValues(token, parsed, verifier);
                checkSignature(token, parsed, verifier);

                DetachedTimestampValidator validator = new DetachedTimestampValidator(token.document(),
                        TimestampType.CONTENT_TIMESTAMP);
                validator.setCertificateVerifier(verifier);
                validator.setValidationTime(Date.from(options.validationTime()));
                validator.setLocale(Locale.ENGLISH);
                DSSDocument timestamped = timestampedData(data, options);
                if (timestamped != null) {
                    validator.setTimestampedData(timestamped);
                }
                // ADR-0023: the aligned policy, the default validation policy of DSS, or a policy file.
                Reports reports = policy.validate(PolicySelection.Kind.DOCUMENT, validator::validateDocument);

                SimpleReport simple = reports.getSimpleReport();
                String id = simple.getFirstTimestampId();
                if (id == null) {
                    throw new IllegalStateException("DSS reports no timestamp for " + options.timestamp());
                }
                output.writeValidated(List.of(
                        new ValidationOutput.Report("diagnostic-data.xml", reports.getXmlDiagnosticData()),
                        new ValidationOutput.Report("detailed-report.xml", reports.getXmlDetailedReport()),
                        new ValidationOutput.Report("simple-report.xml", reports.getXmlSimpleReport()),
                        new ValidationOutput.Report("etsi-validation-report.xml", reports.getXmlValidationReport())),
                        simple.getIndication(id), simple.getSubIndication(id), details(reports, id));
            } catch (RejectedInputException e) {
                output.writeRejected(e);
            }
        });
        return ExitCodes.SUCCESS;
    }

    /**
     * Checks the options of the mode.
     *
     * @throws UsageException if an option is missing, in conflict or not valid
     */
    private static Options check(Arguments arguments) throws UsageException {
        // DSS registers Bouncy Castle when it starts; the digest algorithms below need it now.
        DSSSecurityProvider.initSystemProviders();
        Path timestamp = arguments.timestamp()
                .orElseThrow(() -> new UsageException("--timestamp is required."));
        if (arguments.trustAnchors().isEmpty()) {
            throw new UsageException("--trust-anchor is required.");
        }
        Instant validationTime = arguments.validationTime()
                .orElseThrow(() -> new UsageException("--validation-time is required."));
        Path out = arguments.out().orElseThrow(() -> new UsageException("--out is required."));
        if (arguments.data().isPresent() && arguments.digest().isPresent()) {
            throw new UsageException("--data and --digest are mutually exclusive.");
        }
        if (arguments.digest().isPresent() != arguments.digestAlgorithm().isPresent()) {
            throw new UsageException("--digest and --digest-algorithm must be given together.");
        }
        if (arguments.digest().isEmpty()) {
            return new Options(timestamp, validationTime, out, null, null);
        }
        DigestAlgorithm algorithm = DigestAlgorithm.forName(arguments.digestAlgorithm().get(), null);
        if (algorithm == null) {
            throw new UsageException("--digest-algorithm: unknown algorithm " + arguments.digestAlgorithm().get()
                    + "; use a DSS name such as SHA256, SHA384, SHA512 or SHA3-256.");
        }
        byte[] digest;
        try {
            digest = HexFormat.of().parseHex(arguments.digest().get());
        } catch (IllegalArgumentException e) {
            throw new UsageException("--digest is not hexadecimal: " + arguments.digest().get());
        }
        int length;
        try {
            length = algorithm.getMessageDigest().getDigestLength();
        } catch (NoSuchAlgorithmException e) {
            throw new UsageException("--digest-algorithm: " + algorithm.getName() + " is not available.");
        }
        if (digest.length != length) {
            throw new UsageException("--digest has " + digest.length + " bytes; " + algorithm.getName() + " gives "
                    + length + ".");
        }
        return new Options(timestamp, validationTime, out, algorithm, digest);
    }

    /**
     * Parses the token as DSS does, then makes, on the token alone, the calls
     * that DSS makes on it later during the validation and the building of
     * the reports, so that a token that DSS cannot use is rejected instead of
     * failing the run:
     *
     * <ul>
     * <li>it resolves the algorithm of the message imprint and, when data is
     * given, the digest implementation that DSS computes it with;</li>
     * <li>it decodes ({@link CertificateChecks}) every certificate of
     * SignedData that DSS can convert; those of the certificateValues
     * attribute are decoded later, by {@link #checkCertificateValues}.</li>
     * </ul>
     *
     * Only the exception types that DSS and Bouncy Castle throw for malformed
     * input are caught; any other error remains a failure of the tool.
     *
     * @param hashesData whether DSS computes the digest of data given with {@code --data}
     * @return the parsed token
     */
    private static TimestampToken parse(OfflineSources.Input token, boolean hashesData)
            throws RejectedInputException {
        TimestampToken parsed;
        if (withoutContent(token.content())) {
            // Bouncy Castle fails on it with a NullPointerException when DSS parses the token.
            throw token.rejected(new IllegalArgumentException(
                    "the token has no encapsulated content, where its TSTInfo belongs"));
        }
        try {
            parsed = new TimestampToken(token.content(), TimestampType.CONTENT_TIMESTAMP);
        } catch (TSPException | IOException | CMSException | DSSException | IllegalArgumentException
                | IllegalStateException | ClassCastException | NoSuchElementException | IndexOutOfBoundsException e) {
            throw token.rejected(e);
        }
        DigestAlgorithm algorithm;
        try {
            algorithm = parsed.getMessageImprint().getAlgorithm();
        } catch (IllegalArgumentException e) {
            throw token.rejected(new IllegalArgumentException(
                    "the algorithm of the message imprint is not supported by DSS", e));
        }
        if (hashesData) {
            try {
                DSSUtils.getMessageDigest(algorithm);
            } catch (DSSException e) {
                throw token.rejected(new IllegalArgumentException(
                        "DSS cannot compute the digest algorithm of the message imprint, " + algorithm.getName(), e));
            }
        }
        // Before the certificate source of DSS is read: DSS drops from that source a certificate of SignedData
        // whose public key cannot be decoded, but still uses it later, and fails on it.
        for (CertificateToken certificate : signedDataCertificates(parsed)) {
            decode(token, certificate);
        }
        return parsed;
    }

    /** Decodes a certificate of the token, which a failure rejects. */
    private static void decode(OfflineSources.Input token, CertificateToken certificate)
            throws RejectedInputException {
        try {
            CertificateChecks.decode(certificate);
        } catch (IllegalArgumentException e) {
            throw token.rejected(new IllegalArgumentException("a certificate in the token cannot be decoded", e));
        }
    }

    /**
     * Reports whether a CMS structure that Bouncy Castle can parse has no
     * encapsulated content. A structure that it cannot parse is left to the
     * parser of DSS.
     */
    private static boolean withoutContent(byte[] content) {
        try {
            return new CMSSignedData(content).getSignedContent() == null;
        } catch (CMSException | IllegalArgumentException | IllegalStateException | ClassCastException
                | NoSuchElementException | IndexOutOfBoundsException e) {
            return false;
        }
    }

    /**
     * Checks the ESS signing certificate references of the signer: the
     * ESSCertIDs of the signingCertificate attributes, then the ESSCertIDv2s
     * of the signingCertificateV2 attributes, in their order. The rule follows
     * how DSS 6.5.1 has been observed to behave, with tokens signed again
     * after each change:
     *
     * <ul>
     * <li>an ESSCertIDv2 whose hash algorithm DSS cannot compute makes DSS
     * fail wherever it stands, unless DSS has stopped reading the list at an
     * earlier ESSCertIDv2 whose algorithm it does not know;</li>
     * <li>an ESSCertID with an empty hash and no issuer and serial number
     * makes DSS fail wherever it stands;</li>
     * <li>an ESSCertID with an empty hash but an issuer and serial number
     * makes DSS fail when DSS reaches it before a reference whose hash
     * matches a certificate, and is harmless after one.</li>
     * </ul>
     *
     * A value that does not decode is skipped. The token is rejected only in
     * the cases where DSS fails.
     *
     * @param token the input that holds the token, which a failure rejects
     * @param candidates the certificates of the token and the supplied ones
     */
    static void checkSigningCertificateReferences(OfflineSources.Input token, TimestampToken parsed,
            List<CertificateToken> candidates) throws RejectedInputException {
        AttributeTable attributes = parsed.getSignerInformation().getSignedAttributes();
        if (attributes == null) {
            return;
        }
        boolean matched = false;
        for (ASN1Encodable value : values(attributes, PKCSObjectIdentifiers.id_aa_signingCertificate)) {
            ESSCertID[] ids;
            try {
                ids = SigningCertificate.getInstance(value).getCerts();
            } catch (IllegalArgumentException | IllegalStateException | ClassCastException e) {
                continue;
            }
            for (ESSCertID id : ids) {
                byte[] hash = id.getCertHash();
                boolean empty = hash == null || hash.length == 0;
                if (empty && id.getIssuerSerial() == null) {
                    throw token.rejected(new IllegalArgumentException(
                            "the signing certificate attribute holds an ESSCertID with neither a hash nor an issuer"));
                }
                if (empty && !matched) {
                    throw token.rejected(new IllegalArgumentException(
                            "the signing certificate attribute holds an ESSCertID without a hash before any"
                                    + " reference that matches a certificate"));
                }
                if (!empty && matches(DigestAlgorithm.SHA1, hash, candidates)) {
                    matched = true;
                }
            }
        }
        for (ASN1Encodable value : values(attributes, PKCSObjectIdentifiers.id_aa_signingCertificateV2)) {
            ESSCertIDv2[] ids;
            try {
                ids = SigningCertificateV2.getInstance(value).getCerts();
            } catch (IllegalArgumentException | IllegalStateException | ClassCastException e) {
                continue;
            }
            for (ESSCertIDv2 id : ids) {
                DigestAlgorithm algorithm;
                try {
                    algorithm = DigestAlgorithm.forOID(id.getHashAlgorithm().getAlgorithm().getId());
                } catch (IllegalArgumentException e) {
                    // DSS stops reading the list at an algorithm it does not know.
                    break;
                }
                try {
                    DSSUtils.getMessageDigest(algorithm);
                } catch (DSSException e) {
                    throw token.rejected(new IllegalArgumentException(
                            "the signing certificate attribute uses a hash algorithm that DSS cannot compute, "
                                    + algorithm.getName(), e));
                }
            }
        }
    }

    /** Reports whether the digest of one of the certificates, with the algorithm, is the hash. */
    private static boolean matches(DigestAlgorithm algorithm, byte[] hash, List<CertificateToken> candidates) {
        for (CertificateToken candidate : candidates) {
            if (java.util.Arrays.equals(hash, candidate.getDigest(algorithm))) {
                return true;
            }
        }
        return false;
    }

    /** The values of every attribute of a type, as DSS iterates them. */
    private static List<ASN1Encodable> values(AttributeTable attributes, ASN1ObjectIdentifier type) {
        List<ASN1Encodable> values = new ArrayList<>();
        ASN1EncodableVector vector = attributes.getAll(type);
        for (int i = 0; i < vector.size(); i++) {
            try {
                Attribute attribute = Attribute.getInstance(vector.get(i));
                for (ASN1Encodable value : attribute.getAttrValues()) {
                    values.add(value);
                }
            } catch (RuntimeException e) {
                // DSS does not get past such an attribute either.
            }
        }
        return values;
    }

    /**
     * Returns the certificates of the token, each once: those of the CMS
     * structure that DSS can convert ({@link #signedDataCertificates}), then
     * the others that the certificate source of DSS holds, which are those
     * of the unsigned attribute certificateValues (id-aa-ets-certValues) of
     * the signer. Copies count once, as DSS keeps one certificate token for
     * them.
     */
    private static List<CertificateToken> certificates(TimestampToken parsed) {
        Set<CertificateToken> certificates = new LinkedHashSet<>(signedDataCertificates(parsed));
        certificates.addAll(parsed.getCertificates());
        return new ArrayList<>(certificates);
    }

    /**
     * The certificates of the CMS structure of the token that DSS can
     * convert, each once, including those after one that it cannot. The
     * certificate source of DSS keeps them only up to the first that it
     * cannot convert, but DSS uses the others later: a token holding a
     * certificate that DSS cannot convert, then the certificate of its
     * signer with a subject that cannot be decoded, makes DSS fail, as a
     * test checks against DSS alone.
     */
    private static Set<CertificateToken> signedDataCertificates(TimestampToken parsed) {
        Set<CertificateToken> certificates = new LinkedHashSet<>();
        for (X509CertificateHolder holder : parsed.getTimeStamp().getCertificates().getMatches(null)) {
            try {
                certificates.add(DSSASN1Utils.getCertificate(holder));
            } catch (DSSException e) {
                // DSS cannot use it either.
            }
        }
        return certificates;
    }

    /**
     * Checks the signature of the token with the certificates that DSS tries
     * as its signer: the best candidate found in the token, or, when the
     * token does not hold it, the supplied certificates that match the signer
     * identifier. A signature value or algorithm that cannot be decoded
     * rejects the input that holds the token.
     */
    static void checkSignature(OfflineSources.Input token, TimestampToken parsed,
            CertificateVerifier verifier) throws RejectedInputException {
        for (CertificateToken candidate : signerCandidates(parsed, verifier)) {
            try {
                parsed.isSignedBy(candidate);
            } catch (RuntimeOperatorException | IllegalArgumentException | DSSException e) {
                throw token.rejected(new IllegalArgumentException(
                        "the signature of the token cannot be decoded", e));
            }
        }
    }

    /**
     * The certificates that DSS tries as the signer of a token: the best
     * candidate found in the token, or, when the token does not hold it, the
     * supplied certificates that match the signer identifier.
     */
    private static Set<CertificateToken> signerCandidates(TimestampToken parsed, CertificateVerifier verifier) {
        CertificateValidity best = parsed.getCandidatesForSigningCertificate().getTheBestCandidate();
        Set<CertificateToken> candidates = new HashSet<>();
        if (best == null) {
            return candidates;
        }
        if (best.getCertificateToken() != null) {
            candidates.add(best.getCertificateToken());
        } else if (best.getSignerInfo() != null) {
            candidates.addAll(verifier.getTrustedCertSources().getBySignerIdentifier(best.getSignerInfo()));
            candidates.addAll(verifier.getAdjunctCertSources().getBySignerIdentifier(best.getSignerInfo()));
        }
        return candidates;
    }

    /**
     * Decodes ({@link CertificateChecks}) the certificates of the
     * certificateValues attribute that DSS processes: those among the
     * signers that DSS tries and, transitively, the certificates of the
     * token and the supplied ones whose subject is the issuer name of one of
     * these and whose key verifies its signature. DSS does not process
     * another certificate of that attribute, such as one of the same subject
     * with another key, and does not fail on it, as tests check against DSS
     * alone. The certificates of SignedData are decoded when
     * the token is parsed.
     */
    private static void checkCertificateValues(OfflineSources.Input token, TimestampToken parsed,
            CertificateVerifier verifier) throws RejectedInputException {
        Set<CertificateToken> signedData = signedDataCertificates(parsed);
        List<CertificateToken> pool = new ArrayList<>(certificates(parsed));
        pool.addAll(verifier.getTrustedCertSources().getCertificates());
        pool.addAll(verifier.getAdjunctCertSources().getCertificates());
        // The chain does not end at a trust anchor: a copy of pki/root-ca with its name and key but extensions that
        // DSS cannot decode, next to the anchor, makes DSS alone fail, as a test checks.
        for (CertificateToken certificate : IssuerClosure.of(signerCandidates(parsed, verifier), pool,
                ValidateTimestamp::signedBy)) {
            if (!signedData.contains(certificate)) {
                decode(token, certificate);
            }
        }
    }

    /**
     * Whether the key of the issuer verifies the signature of the
     * certificate. The check is made on the certificate as the JVM holds it,
     * not through the token, so that the state DSS keeps in the token is not
     * changed before the validation. It is the call that the token of DSS
     * makes when it checks a signer, on the same certificate object, so the
     * security providers are those that DSS uses, Bouncy Castle among them.
     */
    private static boolean signedBy(CertificateToken certificate, CertificateToken issuer) {
        try {
            certificate.getCertificate().verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static DSSDocument timestampedData(OfflineSources.Input data, Options options) {
        if (data != null) {
            return data.document();
        }
        if (options.digest() != null) {
            return new DigestDocument(options.digestAlgorithm(), options.digest(), "digest");
        }
        return null;
    }

    /** The details of summary.json for a timestamp. */
    private static Map<String, Object> details(Reports reports, String id) {
        DiagnosticData diagnostic = reports.getDiagnosticData();
        TimestampWrapper timestamp = diagnostic.getTimestampById(id);
        SimpleReport simple = reports.getSimpleReport();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("token-id", id);
        details.put("production-time", timestamp.getProductionTime() == null
                ? null : ValidationOutput.format(timestamp.getProductionTime().toInstant()));
        details.put("produced-by", simple.getProducedBy(id));
        Map<String, Object> imprint = new LinkedHashMap<>();
        XmlDigestMatcher matcher = timestamp.getMessageImprint();
        imprint.put("digest-algorithm", matcher == null || matcher.getDigestMethod() == null
                ? null : matcher.getDigestMethod().getName());
        imprint.put("data-found", timestamp.isMessageImprintDataFound());
        imprint.put("data-intact", timestamp.isMessageImprintDataIntact());
        details.put("message-imprint", imprint);
        details.put("errors", ValidationOutput.messages(simple.getAdESValidationErrors(id)));
        details.put("warnings", ValidationOutput.messages(simple.getAdESValidationWarnings(id)));
        return details;
    }
}
