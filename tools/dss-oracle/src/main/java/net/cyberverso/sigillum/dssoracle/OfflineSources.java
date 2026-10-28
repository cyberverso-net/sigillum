package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

/**
 * Builds the DSS certificate verifier of a validation from the files named on
 * the command line, and nothing else. The trust anchors come from
 * {@code --trust-anchor}, other certificates from {@code --certificate}, CRLs
 * from {@code --crl} and OCSP responses from {@code --ocsp}. The verifier has
 * no source that retrieves certificates (AIA) or revocation data online.
 */
public final class OfflineSources {

    /** The largest input file read, far above any file of the test corpus. */
    static final long MAX_FILE_SIZE = 64L * 1024 * 1024;

    private final List<Input> trustAnchors;
    private final List<Input> certificates;
    private final List<Input> crls;
    private final List<Input> ocspResponses;

    private OfflineSources(List<Input> trustAnchors, List<Input> certificates, List<Input> crls,
            List<Input> ocspResponses) {
        this.trustAnchors = trustAnchors;
        this.certificates = certificates;
        this.crls = crls;
        this.ocspResponses = ocspResponses;
    }

    /**
     * Reads an input file named on the command line.
     *
     * @param option the option that named the file, for the error message
     * @param file the file
     * @return the content of the file
     * @throws IOException if the file is missing, too large or cannot be read
     */
    private static byte[] readFile(String option, Path file) throws IOException {
        try {
            if (Files.isDirectory(file)) {
                throw new IOException(option + " " + file + ": is a directory");
            }
            if (Files.size(file) > MAX_FILE_SIZE) {
                throw new IOException(option + " " + file + ": larger than " + MAX_FILE_SIZE + " bytes");
            }
            return Files.readAllBytes(file);
        } catch (NoSuchFileException e) {
            throw new IOException(option + " " + file + ": no such file", e);
        }
    }

    /**
     * Reads the trust anchors, certificates, CRLs and OCSP responses named on
     * the command line, without parsing them.
     *
     * @param arguments the parsed command line
     * @return the sources, ready to be parsed
     * @throws IOException if a file cannot be read
     */
    public static OfflineSources read(Arguments arguments) throws IOException {
        return new OfflineSources(
                Input.readAll("--trust-anchor", arguments.trustAnchors()),
                Input.readAll("--certificate", arguments.certificates()),
                Input.readAll("--crl", arguments.crls()),
                Input.readAll("--ocsp", arguments.ocspResponses()));
    }

    /**
     * Parses the files with DSS and builds an offline certificate verifier
     * from them. A file is rejected only when DSS cannot use it:
     *
     * <ul>
     * <li>a certificate, when DSS cannot load it, or cannot decode its public
     * key, extensions or subject name ({@link CertificateChecks});</li>
     * <li>a CRL, when DSS cannot load it, when the CRL parser of DSS cannot
     * parse it, or when DSS fails while making revocation tokens from it;</li>
     * <li>an OCSP response, when DSS cannot load it, cannot decode its single
     * responses, does not support its signature algorithm, cannot convert or
     * decode a certificate that it holds, or fails while making revocation
     * tokens from it.</li>
     * </ul>
     *
     * Revocation tokens are made, as DSS makes them during a validation, for
     * every pair of a certificate and an issuer whose subject is the issuer
     * name of that certificate, among the supplied certificates and
     * {@code otherCertificates}. A CRL or OCSP response that DSS parses but
     * that covers none of them, or whose signature does not verify, is kept:
     * the validation reports what follows from it.
     *
     * @param otherCertificates certificates found in the validated object,
     *        such as those of a timestamp token
     * @return the certificate verifier
     * @throws RejectedInputException if DSS cannot use a file
     */
    public CertificateVerifier certificateVerifier(List<CertificateToken> otherCertificates)
            throws RejectedInputException {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        List<CertificateToken> all = new ArrayList<>();
        for (Input anchor : trustAnchors) {
            CertificateToken certificate = anchor.certificate();
            trusted.addCertificate(certificate);
            all.add(certificate);
        }
        CommonCertificateSource adjunct = new CommonCertificateSource();
        for (Input input : certificates) {
            CertificateToken certificate = input.certificate();
            adjunct.addCertificate(certificate);
            all.add(certificate);
        }
        all.addAll(otherCertificates);
        CertificateToken anyCertificate = all.get(0);
        for (Input crl : crls) {
            ExternalResourcesCRLSource source;
            byte[] der;
            try {
                source = new ExternalResourcesCRLSource(crl.document());
                der = CRLUtils.buildCRLBinary(crl.content()).getBinaries();
            } catch (DSSException e) {
                throw crl.rejected(e);
            }
            // Before DSS reads the CRL, no declared length may exceed the remaining bytes by more than the
            // size of the CRL (X.690, clause 8.1.3); see CertificateListBounds.
            Optional<String> tooLong = CertificateListBounds.check(der);
            if (tooLong.isPresent()) {
                throw crl.rejected(new IllegalArgumentException(tooLong.get()));
            }
            try {
                // The parser of DSS, as the validation calls it. Its signature check catches its own errors,
                // so the outcome does not depend on the certificate given.
                CRLUtils.buildCRLValidity(new CRLBinary(der), anyCertificate);
            } catch (IOException | RuntimeException e) {
                // DSS catches every exception of this call during a validation and drops the CRL.
                throw crl.rejected(e);
            }
            makeRevocationTokens(crl, all, source::getRevocationTokens);
        }
        for (Input response : ocspResponses) {
            ExternalResourcesOCSPSource source;
            try {
                source = new ExternalResourcesOCSPSource(response.document());
            } catch (DSSException e) {
                throw response.rejected(e);
            }
            for (EncapsulatedRevocationTokenIdentifier<OCSP> binary : source.getAllRevocationBinaries()) {
                BasicOCSPResp basic = ((OCSPResponseBinary) binary).getBasicOCSPResp();
                X509CertificateHolder[] holders;
                try {
                    // DSS catches every exception of this call during a validation and uses no single response.
                    basic.getResponses();
                } catch (RuntimeException e) {
                    throw response.rejected(e);
                }
                try {
                    // DSS resolves the signature algorithm so when it verifies the response or reports it.
                    AlgorithmIdentifier algorithm = basic.getSignatureAlgorithmID();
                    SignatureAlgorithm.forOidAndParams(algorithm.getAlgorithm().getId(),
                            algorithm.getParameters() == null
                                    ? null : DSSASN1Utils.getDEREncoded(algorithm.getParameters()));
                } catch (DSSException | IllegalArgumentException e) {
                    throw response.rejected(new IllegalArgumentException(
                            "DSS does not support the signature algorithm of the OCSP response", e));
                }
                try {
                    holders = basic.getCerts();
                } catch (IllegalArgumentException | IllegalStateException e) {
                    throw response.rejected(new IllegalArgumentException(
                            "a certificate in the OCSP response cannot be decoded", e));
                }
                for (X509CertificateHolder holder : holders) {
                    try {
                        CertificateChecks.decode(DSSASN1Utils.getCertificate(holder));
                    } catch (DSSException | IllegalArgumentException e) {
                        throw response.rejected(new IllegalArgumentException(
                                "a certificate in the OCSP response cannot be decoded", e));
                    }
                }
            }
            makeRevocationTokens(response, all, source::getRevocationTokens);
        }

        // No AIA source: DSS must not fetch issuer certificates.
        CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
        verifier.setAIASource(null);
        verifier.setTrustedCertSources(trusted);
        verifier.setAdjunctCertSources(adjunct);
        verifier.setCrlSource(new ExternalResourcesCRLSource(
                crls.stream().map(Input::document).toArray(DSSDocument[]::new)));
        verifier.setOcspSource(new ExternalResourcesOCSPSource(
                ocspResponses.stream().map(Input::document).toArray(DSSDocument[]::new)));
        return verifier;
    }

    /**
     * Returns a certificate supplied with {@code --certificate}, as DSS loads
     * it.
     *
     * @param index the position of the certificate among those supplied with
     *        {@code --certificate}
     * @return the certificate
     * @throws RejectedInputException if DSS cannot use the file
     */
    public CertificateToken suppliedCertificate(int index) throws RejectedInputException {
        return certificates.get(index).certificate();
    }

    /**
     * Returns the CRL and OCSP files by the identifiers that DSS gives the
     * revocation data they hold, such as {@code R-...} in its reports. A
     * file that repeats revocation data of an earlier one does not replace
     * it. Call it only after {@link #certificateVerifier(List)} has accepted
     * the files.
     *
     * @return the files, by identifier
     */
    public Map<String, Input> revocationInputs() {
        Map<String, Input> inputs = new LinkedHashMap<>();
        for (Input crl : crls) {
            inputs.putIfAbsent(CRLUtils.buildCRLBinary(crl.content()).asXmlId(), crl);
        }
        for (Input response : ocspResponses) {
            for (EncapsulatedRevocationTokenIdentifier<OCSP> binary
                    : new ExternalResourcesOCSPSource(response.document()).getAllRevocationBinaries()) {
                inputs.putIfAbsent(binary.asXmlId(), response);
            }
        }
        return inputs;
    }

    /**
     * Makes the revocation tokens of a source for every pair of a certificate
     * and its issuer. Copies of a certificate count once, as DSS keeps one
     * certificate token for them, and issuers are found by their subject, so
     * the work grows with the pairs, not with the square of the certificates.
     */
    private static void makeRevocationTokens(Input input, List<CertificateToken> certificates,
            BiFunction<CertificateToken, CertificateToken, ?> tokens) throws RejectedInputException {
        for (Map.Entry<CertificateToken, List<CertificateToken>> pair : issuers(certificates).entrySet()) {
            for (CertificateToken issuer : pair.getValue()) {
                try {
                    tokens.apply(pair.getKey(), issuer);
                } catch (DSSException | IllegalArgumentException | IllegalStateException
                        | NegativeArraySizeException e) {
                    // NegativeArraySizeException: DSS fails so on a CRL entry of indefinite length.
                    throw input.rejected(e);
                }
            }
        }
    }

    /**
     * Returns, for each distinct certificate, in their order, the distinct
     * certificates whose subject is its issuer name.
     *
     * @param certificates the certificates, possibly with copies
     * @return the issuers of each certificate
     */
    static Map<CertificateToken, List<CertificateToken>> issuers(List<CertificateToken> certificates) {
        Set<CertificateToken> distinct = new LinkedHashSet<>(certificates);
        Map<X500Principal, List<CertificateToken>> bySubject = new HashMap<>();
        for (CertificateToken certificate : distinct) {
            bySubject.computeIfAbsent(certificate.getSubject().getPrincipal(), subject -> new ArrayList<>())
                    .add(certificate);
        }
        Map<CertificateToken, List<CertificateToken>> issuers = new LinkedHashMap<>();
        for (CertificateToken certificate : distinct) {
            issuers.put(certificate, bySubject.getOrDefault(certificate.getIssuer().getPrincipal(), List.of()));
        }
        return issuers;
    }

    /**
     * An input file named on the command line, with its content.
     *
     * @param option the option that named the file
     * @param file the file, as named on the command line
     * @param content the content of the file
     */
    public record Input(String option, Path file, byte[] content) {

        /**
         * Reads an input file.
         *
         * @param option the option that named the file
         * @param file the file
         * @return the input
         * @throws IOException if the file is missing, too large or cannot be read
         */
        public static Input read(String option, Path file) throws IOException {
            return new Input(option, file, readFile(option, file));
        }

        static List<Input> readAll(String option, List<Path> files) throws IOException {
            List<Input> inputs = new ArrayList<>();
            for (Path file : files) {
                inputs.add(read(option, file));
            }
            return List.copyOf(inputs);
        }

        /**
         * Returns the content as a DSS document named after the file, without
         * its directory, so that the reports do not depend on where it is.
         *
         * @return the document
         */
        public DSSDocument document() {
            return new InMemoryDocument(content, file.getFileName().toString());
        }

        /**
         * Returns the rejection of this input.
         *
         * @param cause the error of the DSS parser
         * @return the exception to throw
         */
        public RejectedInputException rejected(Throwable cause) {
            return new RejectedInputException(option, file, cause);
        }

        CertificateToken certificate() throws RejectedInputException {
            try {
                CertificateToken certificate = DSSUtils.loadCertificate(content);
                CertificateChecks.decode(certificate);
                return certificate;
            } catch (DSSException | IllegalArgumentException e) {
                throw rejected(e);
            }
        }
    }
}
