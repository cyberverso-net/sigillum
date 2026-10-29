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
        assertValidated(directory, "aligned-1", indication, subIndication);
    }

    private static void assertValidated(Path directory, String policy, String indication, String subIndication)
            throws Exception {
        Map<String, Object> summary = summary(directory);
        assertEquals(3L, summary.get("format-version"));
        ValidateDocumentTest.assertOracle(summary);
        assertEquals("validate-certificate", summary.get("mode"));
        assertEquals(VALIDATION_TIME, summary.get("validation-time"));
        assertEquals(policy, summary.get("policy"), summary.toString());
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
        // DIV-5: the CRL was issued at the instant the certificate expired and shows no status after expiry.
        // The manifest predicts OUT_OF_BOUNDS_NO_POE (ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, NOTE 8).
        assertValidated(result, "INDETERMINATE", "OUT_OF_BOUNDS_NOT_REVOKED");
        assertRevocation(member(summary(result), "details"), "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
    }

    // ADR-0023: the aligned policy differs from the default policy of DSS 6.5.1 in four parameters.

    /** The arguments that validate a certificate of the corpus with its chain and the given revocation data. */
    private static List<String> corpusRun(String certificate, String... revocation) throws IOException {
        Manifest manifest = Manifest.read(CORPUS);
        return corpusArguments(manifest, certificate, List.of(revocation));
    }

    private List<String> withOut(List<String> args, Path out, String... extra) {
        List<String> all = new ArrayList<>(args);
        all.addAll(Arrays.asList(extra));
        all.addAll(List.of("--out", out.toString()));
        return all;
    }

    @Test
    void theAlignedPolicyIsTheDefaultAndAcceptsEd25519() throws Exception {
        List<String> args = corpusRun("pki/signer-ed25519", "crl/ca-ed25519");
        Path absent = temp.resolve("ed25519");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, absent)), stderr());
        assertValidated(absent, "aligned-1", "PASSED", null);
        Path aligned = temp.resolve("ed25519-aligned");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, aligned, "--policy", "aligned")), stderr());
        assertTrue(Arrays.equals(Files.readAllBytes(absent.resolve("summary.json")),
                Files.readAllBytes(aligned.resolve("summary.json"))));
        Path dss = temp.resolve("ed25519-default");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, dss, "--policy", "default")), stderr());
        assertValidated(dss, "default", "INDETERMINATE", "CRYPTO_CONSTRAINTS_FAILURE_NO_POE");
    }

    @Test
    void theAlignedPolicyChecksRevocationFreshness() throws Exception {
        // ETSI EN 319 102-1 V1.4.1, clause 5.2.5.4: the maximum freshness is nextUpdate minus thisUpdate.
        List<String> args = corpusRun("pki/signer-p256", "crl/ca-ecdsa-expired");
        Path aligned = temp.resolve("stale");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, aligned)), stderr());
        assertValidated(aligned, "INDETERMINATE", "TRY_LATER");
        Path dss = temp.resolve("stale-default");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, dss, "--policy", "default")), stderr());
        assertValidated(dss, "default", "PASSED", null);
    }

    @Test
    void theAlignedPolicyFailsOnAnUnknownCriticalExtension() throws Exception {
        List<String> args = corpusRun("pki/signer-unknown-critical-extension", "crl/ca-ecdsa");
        Path aligned = temp.resolve("critical");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, aligned)), stderr());
        assertValidated(aligned, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        Path dss = temp.resolve("critical-default");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, dss, "--policy", "default")), stderr());
        assertValidated(dss, "default", "PASSED", null);
    }

    @Test
    void theAlignedPolicyHonoursOcspNoCheck() throws Exception {
        List<String> args = corpusRun("pki/ocsp-responder", "crl/ca-ecdsa");
        Path aligned = temp.resolve("nocheck");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, aligned)), stderr());
        assertValidated(aligned, "PASSED", null);
        Path dss = temp.resolve("nocheck-default");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, dss, "--policy", "default")), stderr());
        assertValidated(dss, "default", "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
    }

    /** Writes the aligned certificate policy to a file, as a policy file that DSS can load. */
    private Path policyFile(String name) throws Exception {
        String xml = eu.europa.esig.dss.policy.ValidationPolicyFacade.newFacade().marshall(
                AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.CERTIFICATE_BASE)));
        return Files.writeString(temp.resolve(name), xml, StandardCharsets.UTF_8);
    }

    private static String sha256(Path file) throws Exception {
        return java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }

    @Test
    void aPolicyFileIsUsedAndRecordedWithItsDigest() throws Exception {
        Path policy = policyFile("aligned-policy.xml");
        List<String> args = corpusRun("pki/signer-ed25519", "crl/ca-ed25519");
        Path result = temp.resolve("policy-file");
        assertEquals(ExitCodes.SUCCESS, run(withOut(args, result, "--policy", policy.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals(Map.of("file", policy.toString(), "sha256", sha256(policy)), summary.get("policy"));
        assertEquals("PASSED", summary.get("indication"), summary.toString());
        assertTrue(Files.readString(result.resolve("simple-report.xml")).contains("sigillum aligned policy 1"));
    }

    @Test
    void aPolicyFileThatDssCannotLoadIsRejected() throws Exception {
        Path policy = policyFile("broken-policy.xml");
        String valid = Files.readString(policy);
        for (String content : List.of("not a policy", valid.replace("Level=\"FAIL\"", "Level=\"STRICT\""))) {
            Files.writeString(policy, content, StandardCharsets.UTF_8);
            Path result = temp.resolve("policy-rejected-" + content.length());
            List<String> args = underCaEcdsa("signer-p256", "--crl", corpus("crl/ca-ecdsa.crl"),
                    "--policy", policy.toString(), "--out", result.toString());
            assertRejected(args, result, "--policy", policy.toString());
            assertEquals(Map.of("file", policy.toString(), "sha256", sha256(policy)), summary(result).get("policy"));
        }
    }

    @Test
    void aPolicyFileThatDssLoadsButCannotValidateWithIsRejected() throws Exception {
        // Valid against the policy schema, whose Format is any string, but DSS fails during the validation when it
        // reads the dates of AlgoExpirationDate with this format. The aligned policy validates the same inputs,
        // so the failure belongs to the file.
        Path policy = policyFile("bad-format-policy.xml");
        String xml = Files.readString(policy);
        assertTrue(xml.contains("Format=\"yyyy-MM-dd\""), "no date format in the policy");
        Files.writeString(policy, xml.replace("Format=\"yyyy-MM-dd\"", "Format=\"nonsense\""), StandardCharsets.UTF_8);
        eu.europa.esig.dss.validation.policy.ValidationPolicyLoader.fromValidationPolicy(
                new eu.europa.esig.dss.model.FileDocument(policy.toFile())).create();
        Path result = temp.resolve("policy-bad-format");
        assertRejected(underCaEcdsa("signer-p256", "--crl", corpus("crl/ca-ecdsa.crl"),
                "--policy", policy.toString(), "--out", result.toString()), result, "--policy", policy.toString());
    }

    @Test
    void aValidationThatFailsWithEveryPolicyKeepsItsOwnFailure() throws Exception {
        Path policy = policyFile("any-policy.xml");
        PolicySelection selection = PolicySelection.of(Arguments.parse(List.of(
                "validate-certificate", "--policy", policy.toString())));
        // The validation fails with the policy file, then again with the aligned policy: the failure is not the
        // file's, so the first one is thrown, with the second suppressed.
        List<IllegalStateException> failures = new ArrayList<>();
        IllegalStateException thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> selection.validate(PolicySelection.Kind.CERTIFICATE, used -> {
                    IllegalStateException failure = new IllegalStateException("broken input " + failures.size());
                    failures.add(failure);
                    throw failure;
                }));
        assertEquals(2, failures.size());
        assertEquals(failures.get(0), thrown);
        assertEquals(List.of(failures.get(1)), Arrays.asList(thrown.getSuppressed()));
    }

    @Test
    void aMissingPolicyFileIsAFailure() {
        Path result = temp.resolve("policy-missing");
        assertEquals(ExitCodes.FAILURE, run(underCaEcdsa("signer-p256", "--policy",
                temp.resolve("absent.xml").toString(), "--out", result.toString())));
        assertTrue(stderr().contains("absent.xml"), stderr());
        assertFalse(Files.exists(result.resolve("summary.json")));
    }

    @Test
    void aResponseFromAResponderWithoutOcspSigningIsAcceptedWhenTheResponderHasRevocationData() throws Exception {
        // DIV-3 in docs/design/divergences.md. RFC 6960, section 4.2.2.2: a client must reject this response,
        // whose signer is not the CA and lacks id-kp-OCSPSigning. Given the CRL of pki/ca-ecdsa, which covers the
        // signer of the response, DSS 6.5.1 uses the response as the revocation data of pki/signer-p256.
        String response = "ocsp/responder-without-ocsp-signing";
        for (String policy : List.of("aligned", "default")) {
            Path withCrl = temp.resolve("responder-with-crl-" + policy);
            assertEquals(ExitCodes.SUCCESS, run(withOut(corpusRun("pki/signer-p256", response, "crl/ca-ecdsa"),
                    withCrl, "--policy", policy)), stderr());
            assertValidated(withCrl, OraclePolicy.fromCommandName(policy).orElseThrow().identifier(), "PASSED", null);
            assertRevocation(member(summary(withCrl), "details"), "GOOD", "OCSP", "--ocsp",
                    corpus(response + ".der"));
        }
        // Without that CRL, DSS fails for want of revocation data for the signer of the response.
        Path alone = temp.resolve("responder-alone");
        assertEquals(ExitCodes.SUCCESS, run(withOut(corpusRun("pki/signer-p256", response), alone)), stderr());
        assertValidated(alone, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(alone), "details").get("revocation"));
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

    /**
     * Returns a corpus CRL with the last octet of its signature value, the
     * last octet of the file, inverted, so that it stays readable.
     */
    private Path withBadCrlSignature(String path) throws IOException {
        byte[] content = Files.readAllBytes(CORPUS.resolve(path));
        content[content.length - 1] ^= (byte) 0xff;
        return Files.write(temp.resolve("bad-signature-" + Path.of(path).getFileName()), content);
    }

    /**
     * Returns a corpus OCSP response of pki/ocsp-responder with the last
     * octet inverted. The response ends with the certificate of the
     * responder in certs, so the octet belongs to the signature of that
     * certificate: the response itself still verifies, but the chain of its
     * signer cannot be validated.
     */
    private Path withAlteredResponderCertificate(String path) throws IOException {
        byte[] content = Files.readAllBytes(CORPUS.resolve(path));
        content[content.length - 1] ^= (byte) 0xff;
        return Files.write(temp.resolve("altered-responder-" + Path.of(path).getFileName()), content);
    }

    /** Returns a corpus OCSP response with the last octet of its own signature value inverted. */
    private Path withAlteredResponseSignature(String path) throws Exception {
        byte[] content = Files.readAllBytes(CORPUS.resolve(path));
        byte[] signature = ((org.bouncycastle.cert.ocsp.BasicOCSPResp)
                new org.bouncycastle.cert.ocsp.OCSPResp(content).getResponseObject()).getSignature();
        int at = -1;
        for (int i = 0; i + signature.length <= content.length && at < 0; i++) {
            if (Arrays.equals(content, i, i + signature.length, signature, 0, signature.length)) {
                at = i + signature.length - 1;
            }
        }
        assertTrue(at > 0 && at < content.length - 1, "signature not found before certs");
        content[at] ^= (byte) 0xff;
        return Files.write(temp.resolve("altered-signature-" + Path.of(path).getFileName()), content);
    }

    @Test
    void aCrlWhoseSignatureDoesNotVerifyIsKept() throws Exception {
        Path crl = withBadCrlSignature("crl/ca-ecdsa.crl");
        Path result = temp.resolve("bad-crl");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--crl", crl.toString(),
                "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(result), "details").get("revocation"));
    }

    @Test
    void anOcspResponseWhoseOwnSignatureDoesNotVerifyIsSetAsideForTheCrl() throws Exception {
        Path response = withAlteredResponseSignature("ocsp/signer-p256.der");
        Path alone = temp.resolve("bad-response-signature");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                "--out", alone.toString())), stderr());
        assertValidated(alone, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(alone), "details").get("revocation"));
        // With the CRL of the issuer as well, DSS 6.5.1 sets the response aside and uses the CRL, under both
        // policies: this case is not part of DIV-4.
        for (String policy : List.of("aligned", "default")) {
            Path withCrl = temp.resolve("bad-response-signature-with-crl-" + policy);
            assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                    "--crl", corpus("crl/ca-ecdsa.crl"), "--policy", policy, "--out", withCrl.toString())), stderr());
            assertValidated(withCrl, OraclePolicy.fromCommandName(policy).orElseThrow().identifier(), "PASSED", null);
            assertRevocation(member(summary(withCrl), "details"), "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
        }
    }

    @Test
    void anOcspResponseWhoseSignerCannotBeValidatedIsKept() throws Exception {
        Path response = withAlteredResponderCertificate("ocsp/signer-p256.der");
        Path result = temp.resolve("bad-ocsp");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
        assertNull(member(summary(result), "details").get("revocation"));
        // DIV-4: with the CRL of the issuer as well, DSS 6.5.1 still takes the response that covers the
        // certificate, reports that the chain of its signer is not trusted, and does not load the CRL, under both
        // policies.
        for (String policy : List.of("aligned", "default")) {
            Path withCrl = temp.resolve("bad-ocsp-with-crl-" + policy);
            assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", response.toString(),
                    "--crl", corpus("crl/ca-ecdsa.crl"), "--policy", policy, "--out", withCrl.toString())), stderr());
            assertValidated(withCrl, OraclePolicy.fromCommandName(policy).orElseThrow().identifier(), "INDETERMINATE",
                    "CERTIFICATE_CHAIN_GENERAL_FAILURE");
            assertNull(member(summary(withCrl), "details").get("revocation"));
            assertTrue(summary(withCrl).toString().contains("BBB_XCV_CCCBB_REV_ANS"), summary(withCrl).toString());
            assertTrue(summary(withCrl).toString().contains("BBB_XCV_IARDPFC_ANS"), summary(withCrl).toString());
            assertFalse(Files.readString(withCrl.resolve("diagnostic-data.xml")).contains(
                    eu.europa.esig.dss.crl.CRLUtils.buildCRLBinary(
                            Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"))).asXmlId()));
        }
        // A response that covers no certificate of the run leaves DSS to the CRL.
        Path fallback = temp.resolve("fallback");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256",
                "--ocsp", corpus("ocsp/cert-id-wrong-issuer-name-hash.der"),
                "--crl", corpus("crl/ca-ecdsa.crl"), "--out", fallback.toString())), stderr());
        assertValidated(fallback, "PASSED", null);
        assertRevocation(member(summary(fallback), "details"), "GOOD", "CRL", "--crl", corpus("crl/ca-ecdsa.crl"));
    }

    @Test
    void aResponseWithTheStatusUnknownHidesACrlOfTheIssuer() throws Exception {
        // DIV-4 in docs/design/divergences.md: ocsp/unknown covers pki/signer-p256 and gives no status. DSS 6.5.1
        // takes it and does not load the CRL of the issuer, which shows the certificate not revoked.
        for (String policy : List.of("aligned", "default")) {
            Path result = temp.resolve("unknown-with-crl-" + policy);
            assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256", "--ocsp", corpus("ocsp/unknown.der"),
                    "--crl", corpus("crl/ca-ecdsa.crl"), "--policy", policy, "--out", result.toString())), stderr());
            assertValidated(result, OraclePolicy.fromCommandName(policy).orElseThrow().identifier(), "INDETERMINATE",
                    "CERTIFICATE_CHAIN_GENERAL_FAILURE");
            assertNull(member(summary(result), "details").get("revocation"));
            // The messages that the report to the DSS maintainers cites.
            assertTrue(summary(result).toString().contains("BBB_XCV_ISCUKN_ANS"), summary(result).toString());
            assertTrue(summary(result).toString().contains("BBB_XCV_IARDPFC_ANS"), summary(result).toString());
            assertFalse(Files.readString(result.resolve("diagnostic-data.xml")).contains(
                    eu.europa.esig.dss.crl.CRLUtils.buildCRLBinary(
                            Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"))).asXmlId()));
        }
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

    private static String result(Map<String, Object> summary) {
        return "rejected".equals(summary.get("result")) ? "rejected"
                : summary.get("sub-indication") == null ? (String) summary.get("indication")
                : summary.get("indication") + " " + summary.get("sub-indication");
    }

    /**
     * Runs every case of the corpus twice under the aligned policy, which
     * must give identical files and the predicted result or a recorded
     * divergence, and once under the default policy of DSS, whose results
     * are printed for the record and not compared (ADR-0023).
     */
    @Test
    void resultsOnTheCorpusAreStableAndMatchThePredictionsUnderTheAlignedPolicy() throws Exception {
        Manifest manifest = Manifest.read(CORPUS);
        Map<String, List<String>> cases = corpusCases(manifest);
        assertEquals(manifest.ofKind("certificate").size() + manifest.ofKind("crl").size()
                + manifest.ofKind("ocsp-response").size(), cases.size());
        StringBuilder table = new StringBuilder();
        List<String> failures = new ArrayList<>();
        Set<String> policyDependent = new java.util.TreeSet<>();
        int index = 0;
        for (Map.Entry<String, List<String>> entry : cases.entrySet()) {
            List<String> run = entry.getValue();
            assertTrue(run.get(0) != null, entry.getKey() + " names no covered certificate");
            List<String> args = corpusArguments(manifest, run.get(0), run.subList(1, run.size()));
            List<Path> results = new ArrayList<>();
            for (int attempt = 0; attempt < 2; attempt++) {
                Path result = temp.resolve("corpus-" + index + "-" + attempt);
                assertEquals(ExitCodes.SUCCESS, run(withOut(args, result)), entry.getKey() + ": " + stderr());
                results.add(result);
            }
            for (String file : files(results.get(0))) {
                assertTrue(Arrays.equals(Files.readAllBytes(results.get(0).resolve(file)),
                        Files.readAllBytes(results.get(1).resolve(file))), entry.getKey() + " " + file);
            }
            assertEquals(files(results.get(0)), files(results.get(1)), entry.getKey());
            Map<String, Object> summary = summary(results.get(0));
            assertEquals("aligned-1", summary.get("policy"), entry.getKey());
            String actual = result(summary);
            Path dss = temp.resolve("corpus-" + index + "-default");
            assertEquals(ExitCodes.SUCCESS, run(withOut(args, dss, "--policy", "default")),
                    entry.getKey() + ": " + stderr());
            assertEquals("default", summary(dss).get("policy"), entry.getKey());
            String byDefault = result(summary(dss));
            if (!byDefault.equals(actual)) {
                policyDependent.add(entry.getKey());
            }
            String predicted = manifest.get(entry.getKey()).expectedDss().replace('-', '_');
            // A result of DSS that differs from the prediction is recorded in docs/design/divergences.md
            // and named by the field dss-divergence of the artefact in the manifest.
            Manifest.Divergence divergence = manifest.get(entry.getKey()).divergence();
            String recorded = divergence == null ? null : divergence.result().replace('-', '_');
            assertTrue(recorded == null || !recorded.equals(predicted),
                    entry.getKey() + " is listed as a divergence but matches the manifest");
            String expected = recorded == null ? predicted : recorded;
            table.append(String.format("| `%s` | %s | %s | %s |%n", entry.getKey(), predicted, actual,
                    byDefault));
            if (!expected.equals(actual)) {
                failures.add(entry.getKey() + ": expected " + expected + ", DSS gives " + actual);
            }
            index++;
        }
        System.out.println("ValidateCertificateTest: predicted result, aligned policy, default policy:\n" + table);
        assertTrue(failures.isEmpty(), String.join("\n", failures));
        // ADR-0023 and the README of the tool: exactly these cases depend on the four deltas.
        assertEquals(new java.util.TreeSet<>(List.of("pki/signer-ed25519", "crl/ca-ed25519", "ocsp/signer-ed25519",
                "crl/ca-ecdsa-expired", "pki/signer-unknown-critical-extension",
                "ocsp/signer-unknown-critical-extension", "pki/ocsp-responder")), policyDependent);
    }

    /**
     * A first revoked certificate entry whose serial number declares two
     * octets but holds one: DSS reads a zero for the missing octet and goes
     * on to the next entries, so pki/signer-p256-revoked is still found
     * revoked (issue #72).
     */
    @Test
    void aSerialNumberThatOverrunsItsEntryIsReadAsDssReadsIt() throws Exception {
        Path crl = Files.write(temp.resolve("overrun.crl"),
                Crls.caEcdsaWithAnEntryFirst(new byte[] {0x30, 0x03, 0x02, 0x02, 0x05}));
        Path result = temp.resolve("overrun");
        assertEquals(ExitCodes.SUCCESS, run(underCaEcdsa("signer-p256-revoked", "--crl", crl.toString(),
                "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("validated", summary.get("result"), summary.toString());
        assertRevocation(member(summary, "details"), "REVOKED", "CRL", "--crl", crl.toString());
    }

}
