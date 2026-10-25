package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Validates a document with DSS alone, without any code of the tool, as the
 * tests of validate-document run it: with the trust anchor pki/root-ca, the
 * certificate pki/ca-ecdsa and, when asked, the CRLs of both CAs, at the
 * validation time of the corpus, and with a signature policy provider
 * without a data loader. The policy is the aligned policy of the tool unless
 * a policy file or the default policy of DSS is given.
 */
final class DssAlone {

    private static final Path CORPUS = Path.of("..", "..", "testdata");

    private DssAlone() {
    }

    /**
     * The inputs of a validation.
     *
     * @param document the document
     * @param documentName its name, as the tool names it: the file name
     * @param detached the detached content, or {@code null}
     * @param detachedName its name
     * @param policy the policy file, or {@code null} for the built-in policy
     * @param named the built-in policy, used without a file: the aligned
     *        policy unless asked otherwise, as in the tool
     * @param crls whether the CRLs of pki/ca-ecdsa and pki/root-ca are given
     */
    record Inputs(byte[] document, String documentName, byte[] detached, String detachedName, byte[] policy,
            OraclePolicy named, boolean crls, List<byte[]> certificates) {

        static Inputs of(byte[] document, String documentName) {
            return new Inputs(document, documentName, null, null, null, OraclePolicy.ALIGNED, true, List.of());
        }

        Inputs withDetached(byte[] content, String name) {
            return new Inputs(document, documentName, content, name, policy, named, crls, certificates);
        }

        Inputs withPolicy(byte[] file) {
            return new Inputs(document, documentName, detached, detachedName, file, named, crls, certificates);
        }

        Inputs withNamedPolicy(OraclePolicy policy) {
            return new Inputs(document, documentName, detached, detachedName, null, policy, crls, certificates);
        }

        Inputs withoutCrls() {
            return new Inputs(document, documentName, detached, detachedName, policy, named, false, certificates);
        }

        /** The inputs with one more certificate supplied, as with {@code --certificate}. */
        Inputs withCertificate(byte[] certificate) {
            List<byte[]> more = new java.util.ArrayList<>(certificates);
            more.add(certificate);
            return new Inputs(document, documentName, detached, detachedName, policy, named, crls, List.copyOf(more));
        }
    }

    /**
     * Validates the document and builds every report, as the tool writes
     * them.
     *
     * @return the reports
     * @throws RuntimeException if DSS fails
     */
    static Reports validate(Inputs inputs) throws IOException {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(CORPUS.resolve("pki/root-ca.pem"))));
        CommonCertificateSource adjunct = new CommonCertificateSource();
        adjunct.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(CORPUS.resolve("pki/ca-ecdsa.pem"))));
        for (byte[] certificate : inputs.certificates()) {
            adjunct.addCertificate(DSSUtils.loadCertificate(certificate));
        }
        CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
        verifier.setTrustedCertSources(trusted);
        verifier.setAdjunctCertSources(adjunct);
        if (inputs.crls()) {
            verifier.setCrlSource(new ExternalResourcesCRLSource(
                    new InMemoryDocument(Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl")), "ca-ecdsa.crl"),
                    new InMemoryDocument(Files.readAllBytes(CORPUS.resolve("crl/root-ca.crl")), "root-ca.crl")));
        }
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
                new InMemoryDocument(inputs.document(), inputs.documentName()));
        validator.setCertificateVerifier(verifier);
        // As the tool does: the supplied certificates are candidates for the signing certificate.
        CommonCertificateSource signing = new CommonCertificateSource();
        trusted.getCertificates().forEach(signing::addCertificate);
        adjunct.getCertificates().forEach(signing::addCertificate);
        validator.setSigningCertificateSource(signing);
        validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
        validator.setValidationTime(Date.from(Instant.parse("2030-01-15T10:00:00Z")));
        validator.setLocale(java.util.Locale.ENGLISH);
        if (inputs.detached() != null) {
            validator.setDetachedContents(List.<DSSDocument>of(
                    new InMemoryDocument(inputs.detached(), inputs.detachedName())));
        }
        // The aligned policy is the one of the tool (AlignedPolicy); the default and file policies are DSS's own.
        Reports reports = inputs.policy() != null
                ? validator.validateDocument(new InMemoryDocument(inputs.policy(), "policy"))
                : inputs.named() == OraclePolicy.ALIGNED ? validator.validateDocument(AlignedPolicy.forDocuments())
                : validator.validateDocument();
        reports.getXmlDiagnosticData();
        reports.getXmlDetailedReport();
        reports.getXmlSimpleReport();
        reports.getXmlValidationReport();
        return reports;
    }

    /**
     * Validates the document and reports whether DSS failed.
     *
     * @return the failure, or {@code null} when DSS completed the validation
     */
    static Throwable failure(Inputs inputs) throws InterruptedException {
        // On a thread with the stack of the worker of the tool, as the tool runs DSS.
        Throwable[] failure = new Throwable[1];
        Thread thread = new Thread(null, () -> {
            try {
                validate(inputs);
            } catch (RuntimeException | IOException | OutOfMemoryError | StackOverflowError e) {
                failure[0] = e;
            }
        }, "dss-alone", ResourceLimits.STACK_BYTES);
        thread.start();
        thread.join();
        return failure[0];
    }
}
