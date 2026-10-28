package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * Opens a signed document with DSS and makes, before the validation, the
 * calls that DSS makes on the document when it validates it, so that a
 * document that DSS cannot use is rejected instead of failing the run.
 */
final class SignedDocuments {

    private SignedDocuments() {
    }


    /**
     * Opens the document with the DSS validator of its format.
     *
     * @param document the document named with {@code --document}
     * @return the validator, not yet configured
     * @throws RejectedInputException if DSS recognises no format, or cannot
     *         parse the document as one, or if JSON in it is nested deeper
     *         than DSS accepts ({@link JsonDepth})
     */
    static SignedDocumentValidator open(OfflineSources.Input document) throws RejectedInputException {
        Optional<String> tooDeep = JsonDepth.check(document.content());
        if (tooDeep.isPresent()) {
            throw document.rejected(new IllegalArgumentException(tooDeep.get()));
        }
        try {
            return SignedDocumentValidator.fromDocument(document.document());
        } catch (UnsupportedOperationException | IllegalInputException | DSSException | IllegalArgumentException
                | IllegalStateException | ClassCastException | NoSuchElementException
                | IndexOutOfBoundsException e) {
            throw document.rejected(e);
        }
    }

    /**
     * Makes, on the configured validator, the calls that DSS makes on the
     * document when it prepares a validation, and that it does not catch:
     *
     * <ul>
     * <li>it builds the signatures, with their counter-signatures, and the
     * timestamps of the document;</li>
     * <li>for each signature, as DSS adds it for verification, it reads the
     * certificate, CRL and OCSP sources, resolves the signing certificate,
     * which checks the signature value, and reads the timestamps and
     * evidence records;</li>
     * <li>it identifies every certificate reference of a signature, as DSS
     * does in its reports, which fails on a reference that holds no value
     * that identifies a certificate, and requires the CRL and OCSP sources of a
     * signature, which DSS leaves unset after an error that it only logs,
     * and then reports;</li>
     * <li>it decodes ({@link CertificateChecks}) the certificates that DSS
     * then processes and reports: the signing certificate of each signature,
     * or its valid candidates, the certificates of the timestamps, and the
     * certificates of the document and the supplied ones whose subject is
     * the issuer name of one of these, transitively. DSS does not process a
     * certificate of the document outside these chains, and does not fail
     * on it;</li>
     * <li>for each timestamp, it resolves the algorithm of the message
     * imprint and, when DSS computes the imprint, the digest implementation
     * that it computes it with, and
     * makes the checks of {@code validate-timestamp} on the signing
     * certificate references and the signature value of the token.</li>
     * </ul>
     *
     * Only the exception types that DSS and Bouncy Castle throw for malformed
     * input are caught; any other error remains a failure of the tool.
     *
     * @param document the document named with {@code --document}
     * @param validator the validator, configured for the validation
     * @param verifier the certificate verifier of the validation
     * @param detachedContent whether detached content is given, which DSS
     *        hashes for a timestamp given as the document
     * @return the certificates that DSS processes: those decoded above
     * @throws RejectedInputException if DSS cannot use the document
     */
    static List<CertificateToken> check(OfflineSources.Input document, SignedDocumentValidator validator,
            CertificateVerifier verifier, boolean detachedContent) throws RejectedInputException {
        List<CertificateToken> certificates = new ArrayList<>();
        List<CertificateToken> found = new ArrayList<>();
        try {
            List<AdvancedSignature> signatures = new ArrayList<>();
            for (AdvancedSignature signature : validator.getSignatures()) {
                addWithCounterSignatures(signature, signatures);
            }
            List<TimestampToken> detachedTimestamps = validator.getDetachedTimestamps();
            List<TimestampToken> timestamps = new ArrayList<>(detachedTimestamps);
            for (AdvancedSignature signature : signatures) {
                for (CertificateRef reference : signature.getCertificateSource().getAllCertificateRefs()) {
                    // DSS identifies every reference in its reports, and fails on one that holds none of the
                    // values that identify a certificate, such as a digest, an issuer or a key identifier.
                    reference.getDSSIdAsString();
                }
                if (signature.getCRLSource() == null || signature.getOCSPSource() == null) {
                    // DSS logs the error that leaves a source unset, then fails on it when it reports.
                    throw new IllegalArgumentException("DSS cannot read the revocation values of the signature");
                }
                found.addAll(signature.getCertificates());
                CertificateToken signing = signature.getSigningCertificateToken();
                if (signing != null) {
                    certificates.add(signing);
                } else {
                    for (CertificateValidity candidate
                            : signature.getCandidatesForSigningCertificate().getCertificateValidityList()) {
                        if (candidate.isValid() && candidate.getCertificateToken() != null) {
                            certificates.add(candidate.getCertificateToken());
                        }
                    }
                }
                timestamps.addAll(signature.getAllTimestamps());
                signature.getAllEvidenceRecords();
            }
            for (TimestampToken timestamp : timestamps) {
                // DSS processes the signing certificate of a timestamp and its chain, not every certificate that
                // the token holds; the others are only candidates for the chain.
                found.addAll(timestamp.getCertificates());
                CertificateValidity best = timestamp.getCandidatesForSigningCertificate().getTheBestCandidate();
                if (best != null && best.getCertificateToken() != null) {
                    certificates.add(best.getCertificateToken());
                }
            }
            List<CertificateToken> pool = new ArrayList<>(found);
            pool.addAll(certificates);
            pool.addAll(verifier.getTrustedCertSources().getCertificates());
            pool.addAll(verifier.getAdjunctCertSources().getCertificates());
            List<CertificateToken> processed = withIssuers(certificates, pool);
            for (CertificateToken certificate : processed) {
                try {
                    CertificateChecks.decode(certificate);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("a certificate in the document cannot be decoded", e);
                }
            }
            for (TimestampToken timestamp : timestamps) {
                // DSS computes the message imprint of a timestamp of a signature, and that of a timestamp given as
                // the document only when it has the content that the timestamp covers.
                if (detachedContent || !detachedTimestamps.contains(timestamp)) {
                    DSSUtils.getMessageDigest(timestamp.getMessageImprint().getAlgorithm());
                }
                List<CertificateToken> candidates = new ArrayList<>(timestamp.getCertificates());
                candidates.addAll(verifier.getTrustedCertSources().getCertificates());
                candidates.addAll(verifier.getAdjunctCertSources().getCertificates());
                ValidateTimestamp.checkSigningCertificateReferences(document, timestamp, candidates);
                ValidateTimestamp.checkSignature(document, timestamp, verifier);
            }
            return processed;
        } catch (IllegalInputException | DSSException | IllegalArgumentException | IllegalStateException
                | ClassCastException | NoSuchElementException | IndexOutOfBoundsException e) {
            throw document.rejected(e);
        }
    }

    /**
     * Returns the certificates with, transitively, every certificate of the
     * pool whose subject is the issuer name of one of them: the candidates
     * that DSS considers when it builds their chains.
     */
    private static List<CertificateToken> withIssuers(List<CertificateToken> certificates,
            List<CertificateToken> pool) {
        // Copies count once, and issuers are found by their subject, so the work grows with the pairs.
        java.util.Map<javax.security.auth.x500.X500Principal, List<CertificateToken>> bySubject =
                new java.util.HashMap<>();
        for (CertificateToken issuer : new java.util.LinkedHashSet<>(pool)) {
            bySubject.computeIfAbsent(issuer.getSubject().getPrincipal(), subject -> new ArrayList<>()).add(issuer);
        }
        java.util.Set<CertificateToken> result = new java.util.LinkedHashSet<>();
        java.util.Deque<CertificateToken> pending = new java.util.ArrayDeque<>(certificates);
        while (!pending.isEmpty()) {
            CertificateToken certificate = pending.pop();
            if (!result.add(certificate)) {
                continue;
            }
            for (CertificateToken issuer : bySubject.getOrDefault(certificate.getIssuer().getPrincipal(), List.of())) {
                pending.push(issuer);
            }
        }
        return new ArrayList<>(result);
    }

    private static void addWithCounterSignatures(AdvancedSignature signature, List<AdvancedSignature> all) {
        all.add(signature);
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            addWithCounterSignatures(counterSignature, all);
        }
    }
}
