package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests of the validate-certificate mode on the certificates, CRLs and OCSP
 * responses of {@code testdata}, at the validation time of the corpus.
 */
class ValidateCertificateTest {

    private static final Path CORPUS = Path.of("..", "..", "testdata");
    private static final String VALIDATION_TIME = "2030-01-15T10:00:00Z";
    private static final List<String> REPORTS = List.of(
            "diagnostic-data.xml", "detailed-report.xml", "simple-report.xml");

    @TempDir
    Path temp;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(List<String> args) {
        return Main.run(args.toArray(String[]::new), Modes.RUNNER,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    private static String corpus(String path) {
        return CORPUS.resolve(path).toString();
    }

    /**
     * The arguments that validate a certificate of pki/ca-ecdsa with the
     * chain of that CA, without revocation data for the certificate itself
     * and without --out.
     */
    private static List<String> underCaEcdsa(String certificate, String... extra) {
        List<String> args = new ArrayList<>(List.of(
                "validate-certificate",
                "--certificate", corpus("pki/" + certificate + ".pem"),
                "--certificate", corpus("pki/ca-ecdsa.pem"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", VALIDATION_TIME));
        args.addAll(Arrays.asList(extra));
        return args;
    }

    private static Map<String, Object> summary(Path directory) throws IOException {
        return JsonReader.object(Files.readString(directory.resolve("summary.json"), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> member(Map<String, Object> object, String name) {
        return (Map<String, Object>) object.get(name);
    }

    private static List<String> files(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    private static void assertWellFormedXml(Path file) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setNamespaceAware(true);
        assertTrue(factory.newDocumentBuilder().parse(file.toFile()).getDocumentElement() != null, file.toString());
    }

    private static void assertValidated(Path directory, String indication, String subIndication) throws Exception {
        Map<String, Object> summary = summary(directory);
        assertEquals(1L, summary.get("format-version"));
        assertEquals("validate-certificate", summary.get("mode"));
        assertEquals(VALIDATION_TIME, summary.get("validation-time"));
        assertEquals("validated", summary.get("result"), summary.toString());
        assertEquals(indication, summary.get("indication"), summary.toString());
        assertEquals(subIndication, summary.get("sub-indication"), summary.toString());
        List<String> expected = new ArrayList<>(REPORTS);
        expected.add("summary.json");
        expected.sort(null);
        assertEquals(expected, files(directory));
        for (String report : REPORTS) {
            assertWellFormedXml(directory.resolve(report));
        }
        Map<String, Object> details = member(summary, "details");
        assertTrue(details.get("certificate-id") instanceof String id && id.startsWith("C-"), details.toString());
        assertTrue(Files.readString(directory.resolve("simple-report.xml"))
                .contains((String) details.get("certificate-id")), details.toString());
    }

    private static void assertRevocation(Map<String, Object> details, String status, String type, String option,
            String file) {
        Map<String, Object> revocation = member(details, "revocation");
        assertEquals(status, revocation.get("status"), details.toString());
        Map<String, Object> source = member(revocation, "source");
        assertEquals(type, source.get("type"), details.toString());
        assertEquals(option, source.get("input"), details.toString());
        assertEquals(file, source.get("file"), details.toString());
        assertTrue(source.get("revocation-id") instanceof String id && id.startsWith("R-"), details.toString());
    }

    // Acceptance criteria 1 and 2: the certificate is validated with the supplied sources only.

    @Test
    void aValidCertificateWithTheCrlOfItsIssuerPasses() throws Exception {
        Path result = temp.resolve("valid");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256",
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        Map<String, Object> details = member(summary(result), "details");
        assertEquals("sigillum test signer P-256", details.get("common-name"));
        assertEquals("PASSED", member(details, "simple-report").get("indication"));
        assertRevocation(details, "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
        Map<String, Object> revocation = member(details, "revocation");
        assertNull(revocation.get("revocation-time"));
        assertNull(revocation.get("reason"));
        assertEquals("2030-01-14T10:00:00Z", revocation.get("this-update"));
        assertTrue(details.get("errors") instanceof List<?> errors && errors.isEmpty(), details.toString());
        assertTrue(details.get("warnings") instanceof List<?>, details.toString());
    }

    @Test
    void aValidCertificateWithItsOcspResponsePasses() throws Exception {
        Path result = temp.resolve("valid-ocsp");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256",
                "--ocsp", corpus("ocsp/signer-p256.der"), "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        assertRevocation(member(summary(result), "details"), "GOOD", "OCSP", "--ocsp",
                corpus("ocsp/signer-p256.der"));
    }

    @Test
    void aRevokedCertificateIsIndeterminateWithRevokedNoPoe() throws Exception {
        Path result = temp.resolve("revoked");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256-revoked",
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "REVOKED_NO_POE");
        Map<String, Object> details = member(summary(result), "details");
        assertRevocation(details, "REVOKED", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
        Map<String, Object> revocation = member(details, "revocation");
        assertEquals("2029-11-16T10:00:00Z", revocation.get("revocation-time"));
        assertEquals("KEY_COMPROMISE", revocation.get("reason"));
        assertTrue(details.get("errors") instanceof List<?> errors && !errors.isEmpty(), details.toString());
    }

    @Test
    void aRevokedCertificateWithItsOcspResponseNamesTheResponse() throws Exception {
        Path result = temp.resolve("revoked-ocsp");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256-revoked",
                "--ocsp", corpus("ocsp/signer-p256-revoked.der"), "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "REVOKED_NO_POE");
        assertRevocation(member(summary(result), "details"), "REVOKED", "OCSP", "--ocsp",
                corpus("ocsp/signer-p256-revoked.der"));
    }

    @Test
    void anExpiredCertificateIsOutOfBounds() throws Exception {
        Path result = temp.resolve("expired");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-expired",
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", result.toString())), stderr());
        // DSS 6.5.1 reports OUT_OF_BOUNDS_NOT_REVOKED: the CRL, issued after the certificate expired, does not
        // list it. The manifest predicts OUT_OF_BOUNDS_NO_POE.
        assertValidated(result, "INDETERMINATE", "OUT_OF_BOUNDS_NOT_REVOKED");
        assertRevocation(member(summary(result), "details"), "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
    }

    @Test
    void withoutRevocationDataTheChainIsNotConclusive() throws Exception {
        Path result = temp.resolve("no-revocation");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(result), "details").get("revocation"));
    }

    @Test
    void revocationDataThatIsNotAcceptableIsNotReportedAsUsed() throws Exception {
        Path result = temp.resolve("wrong-key");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256",
                "--crl", corpus("crl/ca-ecdsa-wrong-key.crl"), "--out", result.toString())), stderr());
        assertEquals("validated", summary(result).get("result"));
        assertNull(member(summary(result), "details").get("revocation"));
    }

    @Test
    void theIndicationCoversTheChainWhileTheSimpleReportCoversTheCertificate() throws Exception {
        Path result = temp.resolve("not-a-ca");
        assertEquals(ExitCodes.SUCCESS, run(List.of("validate-certificate",
                "--certificate", corpus("pki/signer-under-ca-without-ca-flag.pem"),
                "--certificate", corpus("pki/ca-without-ca-flag.pem"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--crl", corpus("crl/ca-without-ca-flag.crl"), "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", VALIDATION_TIME, "--out", result.toString())), stderr());
        // The issuer is not a CA: the X.509 validation of the chain is not conclusive, although the checks of
        // the certificate itself, which the simple certificate report gives it, pass.
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        Map<String, Object> own = member(member(summary(result), "details"), "simple-report");
        assertEquals("PASSED", own.get("indication"));
        assertNull(own.get("sub-indication"));
    }

    @Test
    void revocationDataGivenTwiceIsNamedByItsFirstFile() throws Exception {
        Path copy = Files.write(temp.resolve("copy.crl"), Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl")));
        Path result = temp.resolve("twice");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--crl", copy.toString(),
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        assertRevocation(member(summary(result), "details"), "GOOD", "CRL", "--crl", copy.toString());
    }

    /** Returns a corpus file with the last octet of its signature value inverted, so that it stays readable. */
    private Path withBadSignature(String path) throws IOException {
        byte[] content = Files.readAllBytes(CORPUS.resolve(path));
        content[content.length - 1] ^= (byte) 0xff;
        return Files.write(temp.resolve("bad-signature-" + Path.of(path).getFileName()), content);
    }

    @Test
    void aCrlWhoseSignatureDoesNotVerifyIsKept() throws Exception {
        Path crl = withBadSignature("crl/ca-ecdsa.crl");
        Path result = temp.resolve("bad-crl");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--crl", crl.toString(),
                "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(result), "details").get("revocation"));
    }

    @Test
    void anOcspResponseWhoseSignatureDoesNotVerifyIsKept() throws Exception {
        Path response = withBadSignature("ocsp/signer-p256.der");
        Path result = temp.resolve("bad-ocsp");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(result), "details").get("revocation"));
        // With the CRL of the issuer as well, DSS 6.5.1 still takes the response that covers the certificate
        // and does not load the CRL.
        Path withCrl = temp.resolve("bad-ocsp-with-crl");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", withCrl.toString())), stderr());
        assertValidated(withCrl, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(withCrl), "details").get("revocation"));
        assertFalse(Files.readString(withCrl.resolve("diagnostic-data.xml")).contains(
                eu.europa.esig.dss.crl.CRLUtils.buildCRLBinary(Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl")))
                        .asXmlId()));
        // A response that covers no certificate of the run leaves DSS to the CRL.
        Path fallback = temp.resolve("fallback");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256",
                "--ocsp", corpus("ocsp/cert-id-wrong-issuer-name-hash.der"),
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", fallback.toString())), stderr());
        assertValidated(fallback, "PASSED", null);
        assertRevocation(member(summary(fallback), "details"), "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
    }

    @Test
    void theTrustAnchorItselfPassesWithoutRevocationData() throws Exception {
        Path result = temp.resolve("anchor");
        assertEquals(ExitCodes.SUCCESS, run(List.of("validate-certificate",
                "--certificate", corpus("pki/root-ca.pem"), "--trust-anchor", corpus("pki/root-ca.pem"),
                "--validation-time", VALIDATION_TIME, "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        assertNull(member(summary(result), "details").get("revocation"));
    }

    @Test
    void theFirstCertificateIsTheOneValidated() throws Exception {
        // Every --certificate after the first is supplied for the chain only: here the CA is validated, not
        // the end entity that follows it.
        Path result = temp.resolve("order");
        assertEquals(ExitCodes.SUCCESS, run(List.of("validate-certificate",
                "--certificate", corpus("pki/ca-ecdsa.pem"), "--certificate", corpus("pki/signer-p256.pem"),
                "--trust-anchor", corpus("pki/root-ca.pem"), "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", VALIDATION_TIME, "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        Map<String, Object> details = member(summary(result), "details");
        assertEquals("sigillum test ECDSA CA", details.get("common-name"));
        assertRevocation(details, "GOOD", "CRL", "--crl", corpus("crl/root-ca.crl"));
    }

    @Test
    void aPemOrDerCertificateGivesTheSameSummary() throws Exception {
        Path der = Files.write(temp.resolve("signer-p256.cer"),
                Pem.decode(Files.readString(CORPUS.resolve("pki/signer-p256.pem"))));
        List<byte[]> summaries = new ArrayList<>();
        for (String file : List.of(corpus("pki/signer-p256.pem"), der.toString())) {
            List<String> args = underCaEcdsa("signer-p256", "--crl", corpus("crl/ca-ecdsa.crl"));
            args.set(args.indexOf(corpus("pki/signer-p256.pem")), file);
            Path result = temp.resolve("encoding-" + summaries.size());
            args.addAll(List.of("--out", result.toString()));
            assertEquals(ExitCodes.SUCCESS, run(args), stderr());
            assertValidated(result, "PASSED", null);
            summaries.add(Files.readAllBytes(result.resolve("summary.json")));
        }
        assertTrue(Arrays.equals(summaries.get(0), summaries.get(1)));
    }

    // Acceptance criterion 3: unparsable input is rejected; tool failures exit non-zero.

    private void assertRejected(List<String> args, Path result, String option, String file) throws IOException {
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals("validate-certificate", summary.get("mode"));
        assertEquals(option, summary.get("input"));
        assertEquals(file, summary.get("file"));
        assertTrue(summary.get("message") instanceof String message && !message.isBlank(), summary.toString());
        assertFalse(summary.containsKey("indication"));
        assertEquals(List.of("summary.json"), files(result));
    }

    @Test
    void anUnparsableCertificateUnderValidationIsRejected() throws Exception {
        Path result = temp.resolve("certificate");
        List<String> args = underCaEcdsa("signer-p256", "--out", result.toString());
        args.set(args.indexOf(corpus("pki/signer-p256.pem")), corpus("crl/ca-ecdsa.crl"));
        assertRejected(args, result, "--certificate", corpus("crl/ca-ecdsa.crl"));
    }

    @Test
    void anUnparsableChainCertificateIsRejected() throws Exception {
        Path result = temp.resolve("chain");
        List<String> args = underCaEcdsa("signer-p256", "--out", result.toString());
        args.set(args.indexOf(corpus("pki/ca-ecdsa.pem")), corpus("timestamps/content.txt"));
        assertRejected(args, result, "--certificate", corpus("timestamps/content.txt"));
    }

    @Test
    void anUnparsableTrustAnchorIsRejected() throws Exception {
        Path result = temp.resolve("anchor");
        List<String> args = underCaEcdsa("signer-p256", "--out", result.toString());
        args.set(args.indexOf(corpus("pki/root-ca.pem")), corpus("crl/root-ca.crl"));
        assertRejected(args, result, "--trust-anchor", corpus("crl/root-ca.crl"));
    }

    @Test
    void anUnparsableCrlIsRejected() throws Exception {
        Path result = temp.resolve("crl");
        assertRejected(underCaEcdsa("signer-p256", "--crl", corpus("pki/signer-p256.pem"),
                "--out", result.toString()), result, "--crl", corpus("pki/signer-p256.pem"));
    }

    @Test
    void anOcspResponseWithoutResponseBytesIsRejected() throws Exception {
        for (String response : List.of("try-later", "unauthorized")) {
            Path result = temp.resolve(response);
            assertRejected(underCaEcdsa("signer-p256", "--ocsp", corpus("ocsp/" + response + ".der"),
                    "--out", result.toString()), result, "--ocsp", corpus("ocsp/" + response + ".der"));
        }
    }

    @Test
    void anOcspResponseWithAnUnknownSignatureAlgorithmIsRejected() throws Exception {
        // DSS fails on it with "Unsupported algorithm" when it reads the signature algorithm of the response.
        Path file = Files.write(temp.resolve("unknown-algorithm.ocsp"),
                OcspResponses.signerP256WithUnknownSignatureAlgorithm());
        for (List<String> extra : List.of(List.<String>of(), List.of("--crl", corpus("crl/ca-ecdsa.crl")))) {
            Path result = temp.resolve("unknown-algorithm-" + extra.size());
            List<String> args = underCaEcdsa("signer-p256", "--ocsp", file.toString());
            args.addAll(extra);
            args.addAll(List.of("--out", result.toString()));
            assertRejected(args, result, "--ocsp", file.toString());
            assertTrue(((String) summary(result).get("message")).contains("1.2.840.10045.4.386"),
                    summary(result).toString());
        }
    }

    @Test
    void aCertificateWithAnUndecodableSubjectIsRejected() throws Exception {
        Path bad = Files.write(temp.resolve("bad-subject.cer"),
                Tokens.certificateWithInvalidUtf8Subject(Files.readString(CORPUS.resolve("pki/signer-p256.pem"))));
        Path result = temp.resolve("bad-subject");
        List<String> args = underCaEcdsa("signer-p256", "--out", result.toString());
        args.set(args.indexOf(corpus("pki/signer-p256.pem")), bad.toString());
        assertRejected(args, result, "--certificate", bad.toString());
    }

    @Test
    void requiredOptionsAreUsageErrors() {
        List<String> complete = underCaEcdsa("signer-p256", "--out", temp.resolve("usage").toString());
        for (String option : List.of("--trust-anchor", "--validation-time", "--out")) {
            List<String> args = new ArrayList<>(complete);
            int index = args.indexOf(option);
            args.remove(index + 1);
            args.remove(index);
            err.reset();
            assertEquals(ExitCodes.USAGE, run(args), option);
            assertTrue(stderr().contains(option + " is required"), stderr());
        }
        err.reset();
        assertEquals(ExitCodes.USAGE, run(List.of("validate-certificate", "--trust-anchor", corpus("pki/root-ca.pem"),
                "--validation-time", VALIDATION_TIME, "--out", temp.resolve("usage").toString())));
        assertTrue(stderr().contains("--certificate is required"), stderr());
        assertFalse(Files.exists(temp.resolve("usage")));
    }

    @Test
    void timestampOptionsAreUsageErrors() {
        for (String option : List.of("--timestamp", "--data", "--digest", "--digest-algorithm")) {
            err.reset();
            Path result = temp.resolve("timestamp-option");
            assertEquals(ExitCodes.USAGE, run(underCaEcdsa("signer-p256", option, corpus("timestamps/content.txt"),
                    "--out", result.toString())), option);
            assertTrue(stderr().contains(option), stderr());
            assertFalse(Files.exists(result));
        }
    }

    @Test
    void aMissingFileIsAFailure() {
        Path result = temp.resolve("missing");
        List<String> args = underCaEcdsa("signer-p256", "--crl", temp.resolve("absent.crl").toString(),
                "--out", result.toString());
        assertEquals(ExitCodes.FAILURE, run(args));
        assertTrue(stderr().contains("absent.crl"), stderr());
        assertFalse(Files.exists(result.resolve("summary.json")));
    }

    @Test
    void anOutputDirectoryThatIsNotEmptyIsAFailure() throws Exception {
        Path result = Files.createDirectories(temp.resolve("used"));
        Files.writeString(result.resolve("old.txt"), "old");
        assertEquals(ExitCodes.FAILURE, run(underCaEcdsa("signer-p256", "--out", result.toString())));
        assertEquals(List.of("old.txt"), files(result));
    }

    // Acceptance criterion 4: two runs on the corpus give identical summaries.

    /**
     * The arguments that validate a certificate of the corpus as the manifest
     * describes it: with its chain, the trust anchor at the end of the chain,
     * the revocation data given, and the revocation data that the CA
     * certificates of the chain link. A certificate without a chain is its
     * own trust anchor.
     */
    private static List<String> corpusArguments(Manifest manifest, String certificate, List<String> revocation) {
        Manifest.Artefact entry = manifest.get(certificate);
        List<String> args = new ArrayList<>(List.of("validate-certificate", "--certificate", corpus(entry.path())));
        List<String> chain = entry.chain();
        String anchor = chain.isEmpty() ? certificate : chain.get(chain.size() - 1);
        Set<String> data = new LinkedHashSet<>(revocation);
        for (String ca : chain.subList(0, Math.max(0, chain.size() - 1))) {
            args.addAll(List.of("--certificate", corpus(manifest.get(ca).path())));
            data.addAll(manifest.get(ca).revocation());
        }
        args.addAll(List.of("--trust-anchor", corpus(manifest.get(anchor).path())));
        for (String id : data) {
            Manifest.Artefact item = manifest.get(id);
            args.addAll(List.of(item.kind().equals("crl") ? "--crl" : "--ocsp", corpus(item.path())));
        }
        args.addAll(List.of("--validation-time", VALIDATION_TIME));
        return args;
    }

    /** The certificate and revocation data of each case of the corpus, by identifier. */
    static Map<String, List<String>> corpusCases(Manifest manifest) {
        Map<String, List<String>> cases = new java.util.LinkedHashMap<>();
        for (Manifest.Artefact certificate : manifest.ofKind("certificate")) {
            List<String> run = new ArrayList<>(List.of(certificate.id()));
            run.addAll(certificate.revocation());
            cases.put(certificate.id(), run);
        }
        for (String kind : List.of("crl", "ocsp-response")) {
            for (Manifest.Artefact data : manifest.ofKind(kind)) {
                cases.put(data.id(), List.of(data.covered(), data.id()));
            }
        }
        return cases;
    }

    /**
     * The results of DSS 6.5.1 that differ from the predictions of
     * testdata/manifest.toml, by identifier. They are tracked in issue #75;
     * every other case must give the result that the manifest predicts.
     */
    private static final Map<String, String> KNOWN_DIFFERENCES = Map.ofEntries(
            Map.entry("pki/signer-ed25519", "INDETERMINATE CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
            Map.entry("crl/ca-ed25519", "INDETERMINATE CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
            Map.entry("ocsp/signer-ed25519", "INDETERMINATE CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
            Map.entry("pki/ocsp-responder", "INDETERMINATE CERTIFICATE_CHAIN_GENERAL_FAILURE"),
            Map.entry("pki/signer-expired", "INDETERMINATE OUT_OF_BOUNDS_NOT_REVOKED"),
            Map.entry("ocsp/signer-expired", "INDETERMINATE OUT_OF_BOUNDS_NOT_REVOKED"),
            Map.entry("pki/ca-expired", "INDETERMINATE OUT_OF_BOUNDS_NOT_REVOKED"),
            Map.entry("pki/signer-not-yet-valid", "INDETERMINATE CERTIFICATE_CHAIN_GENERAL_FAILURE"),
            Map.entry("ocsp/signer-not-yet-valid", "INDETERMINATE CERTIFICATE_CHAIN_GENERAL_FAILURE"),
            Map.entry("pki/signer-under-expired-ca", "INDETERMINATE REVOCATION_OUT_OF_BOUNDS_NO_POE"),
            Map.entry("crl/ca-expired", "INDETERMINATE REVOCATION_OUT_OF_BOUNDS_NO_POE"),
            Map.entry("ocsp/signer-under-expired-ca", "INDETERMINATE REVOCATION_OUT_OF_BOUNDS_NO_POE"),
            Map.entry("pki/signer-unknown-critical-extension", "PASSED"),
            Map.entry("ocsp/signer-unknown-critical-extension", "PASSED"),
            Map.entry("crl/ca-ecdsa-expired", "PASSED"));

    @Test
    void resultsOnTheCorpusAreStableOverTwoRuns() throws Exception {
        Manifest manifest = Manifest.read(CORPUS);
        Map<String, List<String>> cases = corpusCases(manifest);
        assertEquals(manifest.ofKind("certificate").size() + manifest.ofKind("crl").size()
                + manifest.ofKind("ocsp-response").size(), cases.size());
        StringBuilder table = new StringBuilder();
        List<String> failures = new ArrayList<>();
        int index = 0;
        for (Map.Entry<String, List<String>> entry : cases.entrySet()) {
            List<String> run = entry.getValue();
            assertTrue(run.get(0) != null, entry.getKey() + " names no covered certificate");
            List<String> args = corpusArguments(manifest, run.get(0), run.subList(1, run.size()));
            List<Path> results = new ArrayList<>();
            for (int attempt = 0; attempt < 2; attempt++) {
                Path result = temp.resolve("corpus-" + index + "-" + attempt);
                List<String> withOut = new ArrayList<>(args);
                withOut.addAll(List.of("--out", result.toString()));
                assertEquals(ExitCodes.SUCCESS, run(withOut), entry.getKey() + ": " + stderr());
                results.add(result);
            }
            for (String file : files(results.get(0))) {
                assertTrue(Arrays.equals(Files.readAllBytes(results.get(0).resolve(file)),
                        Files.readAllBytes(results.get(1).resolve(file))), entry.getKey() + " " + file);
            }
            assertEquals(files(results.get(0)), files(results.get(1)), entry.getKey());
            Map<String, Object> summary = summary(results.get(0));
            String actual = "rejected".equals(summary.get("result")) ? "rejected"
                    : summary.get("sub-indication") == null ? (String) summary.get("indication")
                    : summary.get("indication") + " " + summary.get("sub-indication");
            String predicted = manifest.get(entry.getKey()).expectedDss().replace('-', '_');
            String expected = KNOWN_DIFFERENCES.getOrDefault(entry.getKey(), predicted);
            assertTrue(!expected.equals(predicted) || !KNOWN_DIFFERENCES.containsKey(entry.getKey()),
                    entry.getKey() + " is listed as a known difference but matches the manifest");
            table.append(String.format("%s | %s | %s | %s%n", entry.getKey(), predicted, actual,
                    predicted.equals(actual) ? "match" : "differs (#75)"));
            if (!expected.equals(actual)) {
                failures.add(entry.getKey() + ": expected " + expected + ", DSS gives " + actual);
            }
            index++;
        }
        System.out.println("ValidateCertificateTest: corpus results against the manifest:\n" + table);
        assertTrue(cases.keySet().containsAll(KNOWN_DIFFERENCES.keySet()), KNOWN_DIFFERENCES.keySet().toString());
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }
}
