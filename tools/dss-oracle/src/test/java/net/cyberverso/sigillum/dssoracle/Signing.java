package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Inputs of the corpus for the tests of the sign mode, a stand-in for
 * {@code sigillum-testpki tsa}, and a validation of signed documents by DSS
 * alone, without any code of the tool.
 */
final class Signing {

    static final Path CORPUS = Path.of("..", "..", "testdata");
    static final String SIGNING_TIME = "2029-12-16T10:00:00Z";
    static final String VALIDATION_TIME = "2030-01-15T10:00:00Z";

    /**
     * A signer of the test PKI.
     *
     * @param label the short name used in the tests
     * @param name the certificate name under pki/
     * @param ca the issuing CA under pki/
     * @param algorithm the DSS signature algorithm to request, or {@code null} for the default
     */
    record Signer(String label, String name, String ca, String algorithm) {

        String certificate() {
            return corpus("pki/" + name + ".pem");
        }

        String key() {
            return corpus("pki/keys/" + name + ".test-key.pem");
        }

        String caCertificate() {
            return corpus("pki/" + ca + ".pem");
        }

        String ocsp() {
            return corpus("ocsp/" + name + ".der");
        }
    }

    static final Signer RSA = new Signer("rsa", "signer-rsa-2048", "ca-rsa", null);
    static final Signer RSA_PSS = new Signer("rsa-pss", "signer-rsa-pss-sha256", "ca-rsa-pss",
            "RSA_SSA_PSS_SHA256_MGF1");
    static final Signer P256 = new Signer("p256", "signer-p256", "ca-ecdsa", null);
    static final Signer ED25519 = new Signer("ed25519", "signer-ed25519", "ca-ed25519", null);
    static final List<Signer> SIGNERS = List.of(RSA, RSA_PSS, P256, ED25519);

    private Signing() {
    }

    static String corpus(String path) {
        return CORPUS.resolve(path).toString();
    }

    /** The arguments of a B-B signature by {@code signer}, without format-specific options and --out. */
    static List<String> base(String format, String level, Signer signer, String document) {
        List<String> args = new ArrayList<>(List.of("sign",
                "--format", format,
                "--level", level,
                "--key", signer.key(),
                "--certificate", signer.certificate(),
                "--chain", signer.caCertificate(),
                "--chain", corpus("pki/root-ca.pem"),
                "--signing-time", SIGNING_TIME,
                "--document", document));
        if (signer.algorithm() != null) {
            args.addAll(List.of("--signature-algorithm", signer.algorithm()));
        }
        return args;
    }

    /** The options of a timestamp from {@code program}, at the signing time. */
    static List<String> timestamp(Path program) {
        return List.of(
                "--tsa-program", program.toString(),
                "--tsa-key", corpus("pki/keys/tsa.test-key.pem"),
                "--tsa-cert", corpus("pki/tsa.pem"),
                "--timestamp-time", SIGNING_TIME);
    }

    /**
     * The options of B-LT: the issuer of the TSA certificate, the trust
     * anchor, the revocation data of both chains, and the time.
     */
    static List<String> longTerm(Signer signer) {
        return List.of(
                "--tsa-chain", corpus("pki/ca-ecdsa.pem"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--ocsp", signer.ocsp(),
                "--ocsp", corpus("ocsp/tsa.der"),
                "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", VALIDATION_TIME);
    }

    /**
     * Writes a POSIX shell script that records its arguments, one per line,
     * in {@code log} and then runs {@link TestTsa} with them. The sign mode
     * runs it as a program, without a shell of its own.
     */
    static Path tsaScript(Path directory, Path log) throws IOException {
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        String script = "#!/bin/sh\n"
                + "printf '%s\\n' \"$@\" > " + quote(log.toString()) + "\n"
                + "exec " + quote(java.toString()) + " -cp " + quote(System.getProperty("java.class.path"))
                + " " + TestTsa.class.getName() + " \"$@\"\n";
        return executable(directory.resolve("tsa.sh"), script);
    }

    /** Writes a POSIX shell script with the given body after the interpreter line. */
    static Path script(Path file, String body) throws IOException {
        return executable(file, "#!/bin/sh\n" + body + "\n");
    }

    private static Path executable(Path file, String text) throws IOException {
        Files.writeString(file, text, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rwx------"));
        return file;
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    /**
     * Validates a signed document with DSS alone at the validation time of
     * the corpus, with the root CA as trust anchor, and only the given
     * certificates and revocation files besides what the signature holds.
     *
     * @param certificates certificate files supplied to DSS, such as the CA of the signer
     */
    static Reports validate(Path signed, List<Path> detached, List<String> revocation, List<String> certificates)
            throws IOException {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(Path.of(corpus("pki/root-ca.pem")))));
        CommonCertificateSource adjunct = new CommonCertificateSource();
        for (String certificate : certificates) {
            adjunct.addCertificate(DSSUtils.loadCertificate(Files.readAllBytes(Path.of(certificate))));
        }
        List<DSSDocument> crls = new ArrayList<>();
        List<DSSDocument> responses = new ArrayList<>();
        for (String file : revocation) {
            DSSDocument document = new InMemoryDocument(Files.readAllBytes(Path.of(file)), Path.of(file)
                    .getFileName().toString());
            (file.endsWith(".crl") ? crls : responses).add(document);
        }
        CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
        verifier.setAIASource(null);
        verifier.setTrustedCertSources(trusted);
        verifier.setAdjunctCertSources(adjunct);
        verifier.setCrlSource(new ExternalResourcesCRLSource(crls.toArray(DSSDocument[]::new)));
        verifier.setOcspSource(new ExternalResourcesOCSPSource(responses.toArray(DSSDocument[]::new)));
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
                new InMemoryDocument(Files.readAllBytes(signed), signed.getFileName().toString()));
        validator.setCertificateVerifier(verifier);
        validator.setValidationTime(Date.from(Instant.parse(VALIDATION_TIME)));
        validator.setLocale(Locale.ENGLISH);
        List<DSSDocument> contents = new ArrayList<>();
        for (Path file : detached) {
            contents.add(new InMemoryDocument(Files.readAllBytes(file), file.getFileName().toString()));
        }
        if (!contents.isEmpty()) {
            validator.setDetachedContents(contents);
        }
        return validator.validateDocument();
    }
}
