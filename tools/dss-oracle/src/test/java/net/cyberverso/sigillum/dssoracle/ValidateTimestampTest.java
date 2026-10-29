package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests of the validate-timestamp mode on the timestamp corpus of
 * {@code testdata/timestamps}, at the validation time of the corpus.
 */
class ValidateTimestampTest {

    private static final Path CORPUS = Path.of("..", "..", "testdata");
    private static final String VALIDATION_TIME = "2030-01-15T10:00:00Z";
    private static final List<String> REPORTS = List.of(
            "diagnostic-data.xml", "detailed-report.xml", "simple-report.xml", "etsi-validation-report.xml");

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

    /** The arguments for a corpus token with the chain and CRLs of pki/tsa, without --out. */
    private static List<String> arguments(String token, String... extra) {
        List<String> args = new ArrayList<>(List.of(
                "validate-timestamp",
                "--timestamp", corpus("timestamps/" + token + ".tst"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--certificate", corpus("pki/ca-ecdsa.pem"),
                "--crl", corpus("crl/ca-ecdsa.crl"),
                "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", VALIDATION_TIME));
        args.addAll(Arrays.asList(extra));
        return args;
    }

    private static List<String> without(List<String> args, String option) {
        List<String> remaining = new ArrayList<>(args);
        int index = remaining.indexOf(option);
        remaining.remove(index + 1);
        remaining.remove(index);
        return remaining;
    }

    private static Map<String, Object> summary(Path directory) throws IOException {
        return JsonReader.object(Files.readString(directory.resolve("summary.json"), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> member(Map<String, Object> object, String name) {
        return (Map<String, Object>) object.get(name);
    }

    private static String sha256Hex(byte[] data) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
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

    private void assertValidated(Path directory, String indication, String subIndication) throws Exception {
        assertValidated(directory, "aligned-1", indication, subIndication);
    }

    private void assertValidated(Path directory, String policy, String indication, String subIndication)
            throws Exception {
        Map<String, Object> summary = summary(directory);
        assertEquals(3L, summary.get("format-version"));
        ValidateDocumentTest.assertOracle(summary);
        assertEquals("validate-timestamp", summary.get("mode"));
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
    }

    // ADR-0023: the validation policy.

    @Test
    void theAlignedPolicyChecksTheFreshnessOfTheRevocationDataOfTheTsa() throws Exception {
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"));
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), corpus("crl/ca-ecdsa-expired.crl"));
        Path aligned = temp.resolve("stale");
        List<String> withOut = new ArrayList<>(args);
        withOut.addAll(List.of("--out", aligned.toString()));
        assertEquals(ExitCodes.SUCCESS, run(withOut), stderr());
        assertValidated(aligned, "INDETERMINATE", "TRY_LATER");
        Path dss = temp.resolve("stale-default");
        withOut = new ArrayList<>(args);
        withOut.addAll(List.of("--policy", "default", "--out", dss.toString()));
        assertEquals(ExitCodes.SUCCESS, run(withOut), stderr());
        assertValidated(dss, "default", "PASSED", null);
    }

    @Test
    void aPolicyFileIsUsedAndRecorded() throws Exception {
        Path policy = Files.writeString(temp.resolve("document-policy.xml"),
                eu.europa.esig.dss.policy.ValidationPolicyFacade.newFacade().marshall(
                        AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.DOCUMENT_BASE))),
                StandardCharsets.UTF_8);
        Path result = temp.resolve("policy-file");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--policy", policy.toString(), "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals(policy.toString(), ((Map<?, ?>) summary.get("policy")).get("file"), summary.toString());
        assertEquals("PASSED", summary.get("indication"), summary.toString());
        Path rejected = temp.resolve("policy-rejected");
        Files.writeString(policy, "<ConstraintsParameters/>", StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--policy", policy.toString(), "--out", rejected.toString())), stderr());
        assertEquals("rejected", summary(rejected).get("result"));
        assertEquals("--policy", summary(rejected).get("input"));
    }

    // Acceptance criterion 1: the token and its message imprint are validated.

    @Test
    void aValidTokenWithItsDataPasses() throws Exception {
        Path result = temp.resolve("valid");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--data", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        Map<String, Object> details = member(summary(result), "details");
        assertEquals("2030-01-14T10:00:00Z", details.get("production-time"));
        Map<String, Object> imprint = member(details, "message-imprint");
        assertEquals("SHA256", imprint.get("digest-algorithm"));
        assertEquals(true, imprint.get("data-found"));
        assertEquals(true, imprint.get("data-intact"));
        assertTrue(details.get("errors") instanceof List<?> errors && errors.isEmpty(), details.toString());
    }

    @Test
    void aValidTokenWithTheDigestOfItsDataPasses() throws Exception {
        Path result = temp.resolve("digest");
        String digest = sha256Hex(Files.readAllBytes(CORPUS.resolve("timestamps/content.txt")));
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--digest", digest.toUpperCase(java.util.Locale.ROOT), "--digest-algorithm", "SHA256",
                "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
        assertEquals(true, member(member(summary(result), "details"), "message-imprint").get("data-intact"));
    }

    @Test
    void theMismatchingImprintTokenFailsWithHashFailure() throws Exception {
        Path result = temp.resolve("mismatch");
        assertEquals(ExitCodes.SUCCESS, run(arguments("imprint-mismatch",
                "--data", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        assertValidated(result, "FAILED", "HASH_FAILURE");
        Map<String, Object> imprint = member(member(summary(result), "details"), "message-imprint");
        assertEquals(true, imprint.get("data-found"));
        assertEquals(false, imprint.get("data-intact"));
    }

    @Test
    void aValidTokenWithAnotherDigestFailsWithHashFailure() throws Exception {
        Path result = temp.resolve("other-digest");
        String digest = sha256Hex("other data".getBytes(StandardCharsets.UTF_8));
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--digest", digest, "--digest-algorithm", "SHA256", "--out", result.toString())), stderr());
        assertValidated(result, "FAILED", "HASH_FAILURE");
    }

    @Test
    void withoutDataTheImprintIsNotChecked() throws Exception {
        Path result = temp.resolve("no-data");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid", "--out", result.toString())), stderr());
        assertValidated(result, "INDETERMINATE", "SIGNED_DATA_NOT_FOUND");
        Map<String, Object> imprint = member(member(summary(result), "details"), "message-imprint");
        assertEquals(false, imprint.get("data-found"));
        assertEquals(false, imprint.get("data-intact"));
    }

    @Test
    void theSuppliedCrlsAreTheOnlyRevocationData() throws Exception {
        Path result = temp.resolve("no-crl");
        List<String> args = without(without(arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--out", result.toString()), "--crl"), "--crl");
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "INDETERMINATE", "CERTIFICATE_CHAIN_GENERAL_FAILURE");
    }

    // Acceptance criterion 3: results on the corpus are stable over two runs.

    /** The DSS results that testdata/manifest.toml predicts for the timestamp corpus, with its content. */
    private static final Map<String, List<String>> PREDICTIONS = Map.of(
            "valid", Arrays.asList("PASSED", null),
            "signer-without-time-stamping", Arrays.asList("INDETERMINATE", "CHAIN_CONSTRAINTS_FAILURE"),
            "imprint-mismatch", Arrays.asList("FAILED", "HASH_FAILURE"),
            "gen-time-after-validation-time", Arrays.asList("PASSED", null));

    @Test
    void resultsOnTheCorpusAreStableOverTwoRunsAndMatchTheManifest() throws Exception {
        for (Map.Entry<String, List<String>> prediction : PREDICTIONS.entrySet()) {
            String token = prediction.getKey();
            Path first = temp.resolve(token + "-1");
            Path second = temp.resolve(token + "-2");
            for (Path result : List.of(first, second)) {
                assertEquals(ExitCodes.SUCCESS, run(arguments(token,
                        "--data", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
                assertValidated(result, prediction.getValue().get(0), prediction.getValue().get(1));
            }
            for (String file : List.of("summary.json", "diagnostic-data.xml", "detailed-report.xml",
                    "simple-report.xml")) {
                assertTrue(Arrays.equals(Files.readAllBytes(first.resolve(file)),
                        Files.readAllBytes(second.resolve(file))), token + " " + file);
            }
            // The namespace prefixes of this report may differ between runs; its content may not.
            assertEquals(XmlContent.of(first.resolve("etsi-validation-report.xml")),
                    XmlContent.of(second.resolve("etsi-validation-report.xml")), token);
        }
    }

    // Acceptance criterion 2: unparsable input is rejected; tool failures exit non-zero.

    @Test
    void anUnparsableTokenIsRejected() throws Exception {
        Path result = temp.resolve("rejected");
        List<String> args = arguments("valid", "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, corpus("timestamps/content.txt"));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"));
        assertEquals("validate-timestamp", summary.get("mode"));
        assertEquals("--timestamp", summary.get("input"));
        assertEquals(corpus("timestamps/content.txt"), summary.get("file"));
        assertTrue(summary.get("message") instanceof String message && !message.isBlank(), summary.toString());
        assertFalse(summary.containsKey("indication"));
        assertEquals(List.of("summary.json"), files(result));
    }

    @Test
    void anUnparsableCertificateIsRejected() throws Exception {
        Path result = temp.resolve("certificate");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--certificate", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"));
        assertEquals("--certificate", summary.get("input"));
    }

    @Test
    void anUnparsableTrustAnchorIsRejected() throws Exception {
        Path result = temp.resolve("anchor");
        List<String> args = arguments("valid", "--out", result.toString());
        args.set(args.indexOf("--trust-anchor") + 1, corpus("crl/root-ca.crl"));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"));
        assertEquals("--trust-anchor", summary.get("input"));
    }

    @Test
    void anUnparsableCrlIsRejected() throws Exception {
        Path result = temp.resolve("crl");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--crl", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"));
        assertEquals("--crl", summary.get("input"));
        assertEquals(corpus("timestamps/content.txt"), summary.get("file"));
        assertTrue(((String) summary.get("message")).contains("CRL"), summary.toString());
    }

    @Test
    void anUnparsableOcspResponseIsRejected() throws Exception {
        Path result = temp.resolve("ocsp");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--ocsp", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"));
        assertEquals("--ocsp", summary.get("input"));
    }

    private Path derCertificate() throws IOException {
        return Files.write(temp.resolve("tsa.cer"), Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem"))));
    }

    private Path truncated(String path, int length) throws IOException {
        byte[] content = Files.readAllBytes(CORPUS.resolve(path));
        return Files.write(temp.resolve("truncated-" + Path.of(path).getFileName()),
                Arrays.copyOf(content, length));
    }

    private void assertRejected(List<String> args, Path result, String option, String file) throws IOException {
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals(option, summary.get("input"));
        assertEquals(file, summary.get("file"));
        assertTrue(summary.get("message") instanceof String message && !message.isBlank(), summary.toString());
        assertEquals(List.of("summary.json"), files(result));
    }

    @Test
    void aCertificateGivenAsACrlIsRejected() throws Exception {
        for (String file : List.of(corpus("pki/tsa.pem"), derCertificate().toString())) {
            Path result = temp.resolve("certificate-as-crl-" + file.length());
            assertRejected(arguments("valid", "--data", corpus("timestamps/content.txt"), "--crl", file,
                    "--out", result.toString()), result, "--crl", file);
        }
    }

    @Test
    void aTruncatedCrlIsRejected() throws Exception {
        Path crl = truncated("crl/ca-ecdsa.crl", 200);
        Path result = temp.resolve("truncated-crl");
        assertRejected(arguments("valid", "--data", corpus("timestamps/content.txt"), "--crl", crl.toString(),
                "--out", result.toString()), result, "--crl", crl.toString());
    }

    @Test
    void aPemCrlIsAccepted() throws Exception {
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"));
        for (String crl : List.of("ca-ecdsa", "root-ca")) {
            Path pem = Files.writeString(temp.resolve(crl + ".pem"),
                    Pem.encode("X509 CRL", Files.readAllBytes(CORPUS.resolve("crl/" + crl + ".crl"))));
            args.set(args.indexOf(corpus("crl/" + crl + ".crl")), pem.toString());
        }
        Path result = temp.resolve("pem-crl");
        args.addAll(List.of("--out", result.toString()));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    private static final byte[] TRAILING = {1, 2, 3, 4, 5, 6, 7};

    private static byte[] withTrailingBytes(byte[] content) {
        byte[] extended = Arrays.copyOf(content, content.length + TRAILING.length);
        System.arraycopy(TRAILING, 0, extended, content.length, TRAILING.length);
        return extended;
    }

    @Test
    void aCrlFollowedByOtherBytesIsUsedAsDssUsesIt() throws Exception {
        Path extended = Files.write(temp.resolve("ca-ecdsa-extended.crl"),
                withTrailingBytes(Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"))));
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"));
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), extended.toString());
        Path result = temp.resolve("extended-crl");
        args.addAll(List.of("--out", result.toString()));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    @Test
    void anOcspResponseFollowedByOtherBytesIsNotRejected() throws Exception {
        byte[] response = OcspResponses.wellFormed();
        List<byte[]> summaries = new ArrayList<>();
        for (byte[] content : List.of(response, withTrailingBytes(response))) {
            Path file = Files.write(temp.resolve("response-" + content.length + ".ocsp"), content);
            Path result = temp.resolve("ocsp-" + content.length);
            assertEquals(ExitCodes.SUCCESS, run(arguments("valid", "--data", corpus("timestamps/content.txt"),
                    "--ocsp", file.toString(), "--out", result.toString())), stderr());
            assertValidated(result, "PASSED", null);
            summaries.add(Files.readAllBytes(result.resolve("summary.json")));
        }
        assertTrue(Arrays.equals(summaries.get(0), summaries.get(1)));
    }

    @Test
    void anOcspResponseWithAnUnknownSignatureAlgorithmIsRejected() throws Exception {
        // DSS fails on it with "Unsupported algorithm" when it reads the signature algorithm of the response.
        Path file = Files.write(temp.resolve("unknown-algorithm.ocsp"),
                OcspResponses.signerP256WithUnknownSignatureAlgorithm());
        Path result = temp.resolve("unknown-algorithm");
        assertRejected(arguments("valid", "--data", corpus("timestamps/content.txt"), "--ocsp", file.toString(),
                "--out", result.toString()), result, "--ocsp", file.toString());
    }

    @Test
    void anOcspResponseWithAMalformedProducedAtIsRejected() throws Exception {
        Path file = Files.write(temp.resolve("produced-at.ocsp"), OcspResponses.withMalformedProducedAt());
        Path result = temp.resolve("produced-at");
        assertRejected(arguments("valid", "--ocsp", file.toString(), "--out", result.toString()), result,
                "--ocsp", file.toString());
    }

    @Test
    void aCrlWhoseOuterLengthDssIgnoresIsUsed() throws Exception {
        // DSS uses a CRL whose outer SEQUENCE declares a wrong length; a strict DER decoder refuses it.
        byte[] crl = Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"));
        crl[3] = (byte) 0xd6;
        Path file = Files.write(temp.resolve("outer-length.crl"), crl);
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"));
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), file.toString());
        Path result = temp.resolve("outer-length");
        args.addAll(List.of("--out", result.toString()));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    @Test
    void anOcspResponseWithAnotherStatusAndResponseBytesIsUsedAsDssUsesIt() throws Exception {
        List<Map<String, Object>> summaries = new ArrayList<>();
        byte[] response = OcspResponses.forTsa();
        List<byte[]> responses = List.of(response, OcspResponses.withStatus(response, 128));
        for (int i = 0; i < responses.size(); i++) {
            Path file = Files.write(temp.resolve("status-" + i + ".ocsp"), responses.get(i));
            Path result = temp.resolve("status-" + i);
            assertEquals(ExitCodes.SUCCESS, run(arguments("valid", "--data", corpus("timestamps/content.txt"),
                    "--ocsp", file.toString(), "--out", result.toString())), stderr());
            assertEquals("validated", summary(result).get("result"), summary(result).toString());
            summaries.add(summary(result));
        }
        assertEquals(summaries.get(0).get("indication"), summaries.get(1).get("indication"));
    }

    @Test
    void theSignatureIsCheckedWithASuppliedCertificateWhenTheTokenHasNone() throws Exception {
        byte[] withoutCertificates = Tokens.withoutCertificates(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")));
        Path intact = Files.write(temp.resolve("no-certificates.tst"), withoutCertificates);
        Path malformed = Files.write(temp.resolve("no-certificates-malformed.tst"),
                Tokens.withMalformedSignature(withoutCertificates));
        Path first = temp.resolve("supplied-intact");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--certificate", corpus("pki/tsa.pem"), "--out", first.toString());
        args.set(args.indexOf("--timestamp") + 1, intact.toString());
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(first, "PASSED", null);
        Path second = temp.resolve("supplied-malformed");
        args.set(args.indexOf("--timestamp") + 1, malformed.toString());
        args.set(args.indexOf("--out") + 1, second.toString());
        assertRejected(args, second, "--timestamp", malformed.toString());
    }

    @Test
    void aSuppliedSigningCertificateWithAnUndecodableSubjectIsRejected() throws Exception {
        Path token = Files.write(temp.resolve("no-certificates.tst"), Tokens.withoutCertificates(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))));
        Path certificate = Files.write(temp.resolve("tsa-invalid-utf8.cer"),
                Tokens.certificateWithInvalidUtf8Subject(Files.readString(CORPUS.resolve("pki/tsa.pem"))));
        Path result = temp.resolve("invalid-utf8-certificate");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--certificate", certificate.toString(), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertRejected(args, result, "--certificate", certificate.toString());
    }

    @Test
    void aTokenWhoseImprintAlgorithmCannotBeComputedIsRejectedWhenDataIsGiven() throws Exception {
        for (String oid : List.of("2.16.840.1.101.3.4.2.11", "2.16.840.1.101.3.4.2.12")) {
            Path token = Files.write(temp.resolve("shake-" + oid + ".tst"), Tokens.withImprintAlgorithm(
                    Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")), oid));
            Path result = temp.resolve("shake-" + oid);
            List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                    "--out", result.toString());
            args.set(args.indexOf("--timestamp") + 1, token.toString());
            assertRejected(args, result, "--timestamp", token.toString());
            // Without data DSS computes no digest, and the token is validated.
            Path withoutData = temp.resolve("shake-no-data-" + oid);
            args = arguments("valid", "--out", withoutData.toString());
            args.set(args.indexOf("--timestamp") + 1, token.toString());
            assertEquals(ExitCodes.SUCCESS, run(args), stderr());
            assertEquals("validated", summary(withoutData).get("result"));
        }
    }

    /**
     * The fourth byte of a UTCTime length becomes 0x84, so the CRL declares
     * a time of about 858 MB in a file of 570 bytes. DSS alone has been
     * observed to use memory in proportion to such a length: with a small
     * heap the run fails, with a large one DSS makes no usable token from the
     * CRL. The tool must reject the CRL whatever the heap, so the run uses a
     * small heap in a new JVM.
     */
    @Test
    void aCrlDeclaringALengthBeyondTheHeapIsRejected() throws Exception {
        byte[] crl = Files.readAllBytes(CORPUS.resolve("crl/root-ca.crl"));
        crl[103] = (byte) 0x84;
        Path file = Files.write(temp.resolve("huge-length.crl"), crl);
        Path result = temp.resolve("huge-length");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx64m",
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf(corpus("crl/root-ca.crl")), file.toString());
        command.addAll(args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, process.waitFor(), output);
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals("--crl", summary.get("input"));
    }

    /**
     * Issue #72, case 1: the TBSCertList tag of crl/root-ca loses its
     * constructed bit and its nextUpdate declares about 858 MB. DSS reads
     * the TBSCertList whatever its tag, so the CRL must be rejected in a
     * small heap, not end the run with an OutOfMemoryError.
     */
    @Test
    void aCrlWithAPrimitiveTbsCertListDeclaringALengthBeyondTheHeapIsRejected() throws Exception {
        byte[] crl = Files.readAllBytes(CORPUS.resolve("crl/root-ca.crl"));
        crl[4] = 0x10;
        crl[103] = (byte) 0x84;
        Path file = Files.write(temp.resolve("primitive-tbs.crl"), crl);
        Path result = temp.resolve("primitive-tbs");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx64m",
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf(corpus("crl/root-ca.crl")), file.toString());
        command.addAll(args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, process.waitFor(), output);
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals("--crl", summary.get("input"));
    }

    /** Issue #72, case 2: DSS ignores the bytes after a CRL, even when they declare a large length. */
    @Test
    void aCrlFollowedByAnElementDeclaringALargeLengthIsUsedAsDssUsesIt() throws Exception {
        byte[] original = Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"));
        int n = 0;
        for (byte[] trailing : new byte[][] {
            {0x04, (byte) 0x84, 0x03, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            {0x04, (byte) 0x84, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff}}) {
            byte[] crl = Arrays.copyOf(original, original.length + trailing.length);
            System.arraycopy(trailing, 0, crl, original.length, trailing.length);
            assertCrlUsed(crl, "trailing-length-" + n++);
        }
    }

    /**
     * Issue #72, case 3: the signatureValue BIT STRING of crl/root-ca, at
     * offset 181, gets the constructed bit. DSS reads its contents as the
     * signature value and makes a usable revocation token.
     */
    @Test
    void aCrlWhoseSignatureValueHasTheConstructedBitIsUsedAsDssUsesIt() throws Exception {
        for (int tag : new int[] {0x23, 0x63, 0xa3, 0xe3}) {
            byte[] crl = Files.readAllBytes(CORPUS.resolve("crl/root-ca.crl"));
            crl[181] = (byte) tag;
            Path file = Files.write(temp.resolve("constructed-" + tag + ".crl"), crl);
            Path result = temp.resolve("constructed-" + tag);
            List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                    "--out", result.toString());
            args.set(args.indexOf(corpus("crl/root-ca.crl")), file.toString());
            assertEquals(ExitCodes.SUCCESS, run(args), stderr());
            assertValidated(result, "PASSED", null);
        }
    }

    /**
     * Issue #72, case 4: the certificate of pki/tsa, with invalid UTF-8 in
     * its subject, is carried only in the unsigned certificateValues
     * attribute. DSS takes it from there and fails on it while building its
     * reports, so the token is rejected.
     */
    @Test
    void aTokenWithAnUndecodableCertificateInItsCertificateValuesIsRejected() throws Exception {
        byte[] certificate = Tokens.certificateWithInvalidUtf8Subject(
                Files.readString(CORPUS.resolve("pki/tsa.pem")));
        assertTokenRejected(Tokens.withCertificateValues(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")), certificate), "cert-values-utf8");
    }

    /** The certificate of pki/tsa in the certificateValues attribute only is used as DSS uses it. */
    @Test
    void aTokenWithItsCertificateInItsCertificateValuesIsValidated() throws Exception {
        byte[] certificate = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        Path token = Files.write(temp.resolve("cert-values.tst"), Tokens.withCertificateValues(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")), certificate));
        Path result = temp.resolve("cert-values");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    /**
     * Runs a token through the tool and through DSS alone, with the corpus
     * chain, CRLs and content, and requires the outcome of DSS: rejected
     * exactly when DSS alone fails, otherwise validated with its indication.
     */
    private void assertAsDssAlone(byte[] content, String name) throws Exception {
        Path token = Files.write(temp.resolve(name + ".tst"), content);
        Path result = temp.resolve(name);
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        err.reset();
        int code = run(args);
        MutationTest.RawResult alone = MutationTest.rawDss(MutationTest.Setup.corpus(content));
        String dss = alone.failure() != null ? "fails: " + alone.failure() : "validates: " + alone.indication();
        assertEquals(ExitCodes.SUCCESS, code, name + ": " + stderr() + " (DSS alone " + dss + ")");
        Map<String, Object> summary = summary(result);
        if (alone.failure() != null) {
            assertEquals("rejected", summary.get("result"), name + ": " + summary + " (DSS alone " + dss + ")");
            assertEquals("--timestamp", summary.get("input"));
        } else {
            assertEquals("validated", summary.get("result"), name + ": " + summary + " (DSS alone " + dss + ")");
            assertEquals(alone.indication(), summary.get("indication") + " " + summary.get("sub-indication"),
                    name + ": " + summary);
        }
    }

    /**
     * An unrelated certificate with invalid UTF-8 in its subject, next to
     * the certificate of pki/tsa in certificateValues: DSS does not process
     * it, and validates the token (issue #72).
     */
    @Test
    void anUnrelatedUndecodableCertificateInTheCertificateValuesIsNotRejected() throws Exception {
        byte[] tsa = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        byte[] unrelated = Tokens.certificateWithInvalidUtf8Subject(
                Files.readString(CORPUS.resolve("pki/signer-p256.pem")));
        byte[] token = Tokens.withCertificateValues(Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")),
                tsa, unrelated);
        assertNull(MutationTest.rawDss(MutationTest.Setup.corpus(token)).failure());
        assertAsDssAlone(token, "cert-values-unrelated");
    }

    /**
     * The certificate of pki/tsa in certificateValues, with a copy of its
     * issuer pki/ca-ecdsa whose extensions DSS cannot decode, or with a
     * certificate of the same subject and another key, which did not issue
     * it, and whose extensions DSS cannot decode either: the tool must give
     * the outcome of DSS alone (issue #72).
     */
    @Test
    void certificatesWithTheSubjectOfTheIssuerInTheCertificateValuesAreTreatedAsDssTreatsThem() throws Exception {
        byte[] tsa = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        byte[] valid = Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"));
        byte[] issuer = Tokens.caEcdsaWithMalformedAuthorityKeyIdentifier();
        byte[] other = Tokens.otherKeyWithTheSubjectOfCaEcdsa();
        for (byte[] certificate : List.of(issuer, other)) {
            assertThrows(IllegalArgumentException.class,
                    () -> CertificateChecks.decode(DSSUtils.loadCertificate(certificate)));
        }
        assertAsDssAlone(Tokens.withCertificateValues(valid, tsa, issuer), "cert-values-bad-issuer");
        assertAsDssAlone(Tokens.withCertificateValues(valid, tsa, other), "cert-values-other-key");
    }

    /**
     * A revokedCertificates of indefinite length, then a signatureValue
     * declaring 1 GiB: the run must end with exit code 0 in a JVM with a
     * heap of 128 MiB (issue #72).
     */
    @Test
    void anIndefiniteRevokedCertificatesBeforeALongSignatureEndsWithinASmallHeap() throws Exception {
        Path crl = Files.write(temp.resolve("indefinite-revoked.crl"),
                Crls.caEcdsaWithIndefiniteRevokedCertificatesAndALongSignature());
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx128m",
                "-cp", System.getProperty("java.class.path"), HeapProbe.class.getName(), crl.toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);
    }

    /**
     * SignedData holding a certificate that DSS cannot convert, then the
     * certificate of pki/tsa with invalid UTF-8 in its subject, and the
     * reverse order: the tool must give the outcome of DSS alone in both.
     */
    @Test
    void aCertificateAfterOneThatDssCannotConvertIsTreatedAsDssTreatsIt() throws Exception {
        byte[] unconvertible = Tokens.caEcdsaWithMalformedBasicConstraints();
        assertThrows(DSSException.class, () -> DSSASN1Utils.getCertificate(new X509CertificateHolder(unconvertible)));
        byte[] badTsa = Tokens.certificateWithInvalidUtf8Subject(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        byte[] valid = Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"));
        assertAsDssAlone(Tokens.withCertificates(valid, unconvertible, badTsa), "unconvertible-then-bad-tsa");
        assertAsDssAlone(Tokens.withCertificates(valid, badTsa, unconvertible), "bad-tsa-then-unconvertible");
        byte[] tsa = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        assertAsDssAlone(Tokens.withCertificates(valid, unconvertible, tsa), "unconvertible-then-tsa");
    }

    /** Runs the valid token with the given number of copies of its certificates, and returns the time taken. */
    private long copiesRun(byte[] content, String name) throws Exception {
        Path token = Files.write(temp.resolve(name + ".tst"), content);
        Path result = temp.resolve(name);
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        long start = System.nanoTime();
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        long elapsed = System.nanoTime() - start;
        assertValidated(result, "PASSED", null);
        return elapsed;
    }

    /**
     * Issue #72, case 5: a token holding 10,000 copies of its certificate.
     * DSS keeps one certificate token for them. The tool runs DSS once and
     * its own checks, which must not make the run much slower than DSS
     * alone: at most six times as long, with a second of margin.
     * Before the fix, the checks made revocation tokens and decoded the
     * certificate once per copy, and the run took about fourteen times as
     * long as DSS alone.
     */
    @Test
    void copiesOfACertificateInATokenDoNotMakeTheChecksSlowerThanDss() throws Exception {
        byte[] valid = Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"));
        byte[] copies = Tokens.withCopiesOfItsCertificates(valid, 10_000);
        // Warm up both paths once, so that neither pays for loading classes.
        copiesRun(Tokens.withCopiesOfItsCertificates(valid, 10), "copies-warm-up");
        MutationTest.rawDss(MutationTest.Setup.corpus(Tokens.withCopiesOfItsCertificates(valid, 10)));
        long start = System.nanoTime();
        MutationTest.RawResult alone = MutationTest.rawDss(MutationTest.Setup.corpus(copies));
        long dss = System.nanoTime() - start;
        assertNull(alone.failure());
        assertTrue(alone.indication().startsWith("PASSED"), alone.indication());
        long tool = copiesRun(copies, "copies");
        String timings = "10000 copies: tool " + tool / 1_000_000 + " ms, DSS alone " + dss / 1_000_000 + " ms";
        System.out.println(timings);
        assertTrue(tool < 6 * dss + 1_000_000_000L, timings);
    }

    /** Runs the tool in a new JVM with a heap, with the CRL in place of crl/ca-ecdsa, and returns the summary. */
    private Map<String, Object> runWithHeap(String heap, byte[] crl, String name) throws Exception {
        Path file = Files.write(temp.resolve(name + ".crl"), crl);
        Path result = temp.resolve(name);
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), heap, "-XX:+UseSerialGC",
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), file.toString());
        command.addAll(args);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, process.waitFor(), output);
        return summary(result);
    }

    /**
     * A revokedCertificates of indefinite length whose contents start with
     * an AlgorithmIdentifier and a BIT STRING declaring 1 GiB: DSS alone, in
     * a heap of 64 MiB, runs out of memory on it, so it reads that BIT
     * STRING, and the tool must reject the CRL in the same heap (issue #72).
     */
    @Test
    void aLongBitStringInAnIndefiniteRevokedCertificatesIsRejected() throws Exception {
        byte[] crl = Crls.caEcdsaWithAnAlgorithmAndALongBitStringInIndefiniteRevokedCertificates();
        Path file = Files.write(temp.resolve("algorithm-in-revoked-alone.crl"), crl);
        Process alone = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx64m", "-XX:+UseSerialGC",
                "-cp", System.getProperty("java.class.path"), CrlAloneProbe.class.getName(), file.toString()))
                .redirectErrorStream(true).start();
        String output = new String(alone.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, alone.waitFor(), output);
        assertTrue(output.contains("OutOfMemoryError"), output);
        Map<String, Object> summary = runWithHeap("-Xmx64m", crl, "algorithm-in-revoked");
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals("--crl", summary.get("input"));
    }

    /**
     * crl/ca-ecdsa followed by 16 MiB of zeros, which DSS ignores: the check
     * must not keep a record per trailing element, and the token is
     * validated in a heap of 256 MiB (issue #72).
     */
    @Test
    void aCrlFollowedByManyZerosIsUsedWithinAModerateHeap() throws Exception {
        byte[] original = Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"));
        byte[] padded = Arrays.copyOf(original, original.length + 16 * 1024 * 1024);
        Map<String, Object> summary = runWithHeap("-Xmx256m", padded, "zero-padded");
        assertEquals("validated", summary.get("result"), summary.toString());
        assertEquals("PASSED", summary.get("indication"), summary.toString());
    }

    /** Runs DSS alone in a new JVM with a heap of 64 MiB, with the CRL in place of crl/ca-ecdsa, and returns its output. */
    private String dssAloneWithSmallHeap(byte[] crl, String name) throws Exception {
        Path file = Files.write(temp.resolve(name + "-alone.crl"), crl);
        Process alone = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx64m", "-XX:+UseSerialGC",
                "-cp", System.getProperty("java.class.path"), CrlAloneProbe.class.getName(), file.toString()))
                .redirectErrorStream(true).start();
        String output = new String(alone.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, alone.waitFor(), output);
        return output;
    }

    /**
     * Runs DSS alone and the tool, each in a heap of 64 MiB, with the CRL,
     * and requires the tool to reject it exactly when DSS alone runs out of
     * memory on it, and to validate it otherwise.
     */
    private String assertCrlAsDssAloneInASmallHeap(byte[] crl, String name) throws Exception {
        String alone = dssAloneWithSmallHeap(crl, name);
        boolean outOfMemory = alone.contains("OutOfMemoryError");
        Map<String, Object> summary = runWithHeap("-Xmx64m", crl, name);
        assertEquals(outOfMemory ? "rejected" : "validated", summary.get("result"),
                name + ": " + summary + " (DSS alone: " + alone.strip() + ")");
        return alone;
    }

    /**
     * A first revoked certificate entry of 7 contents octets whose serial number
     * declares about 1 GiB: the tool rejects the CRL exactly when DSS alone
     * runs out of memory on it in a small heap (issue #72).
     */
    @Test
    void aSerialNumberDeclaringALargeLengthInAShortEntryIsTreatedAsDssTreatsIt() throws Exception {
        assertCrlAsDssAloneInASmallHeap(Crls.caEcdsaWithAnEntryFirst(new byte[] {0x30, 0x07, 0x02, (byte) 0x84,
            0x3f, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x05}), "long-serial");
    }

    /**
     * A first entry of 2 contents octets, the identifier and length octets
     * of a serial number of 2 contents octets, then an entry declaring about
     * 1 GiB: whether DSS reads that entry shows whether it reads the
     * contents of the serial number past its entry, and the tool must
     * agree (issue #72).
     */
    @Test
    void aSerialNumberStartingAtTheEndOfItsEntryIsReadAsDssReadsIt() throws Exception {
        byte[] entries = {0x30, 0x02, 0x02, 0x02, 0x30, (byte) 0x84, 0x3f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            0x02, 0x01, 0x05};
        String alone = assertCrlAsDssAloneInASmallHeap(Crls.caEcdsaWithAnEntryFirst(entries), "serial-at-end");
        // DSS alone read the CRL and reported an indication, not only that it did not run out of memory.
        assertTrue(alone.startsWith("indication "), alone);
    }

    /**
     * pki/tsa in certificateValues with a copy of pki/root-ca, of the same
     * name and key, whose extensions DSS cannot decode: the tool must give
     * the outcome of DSS alone (issue #72).
     */
    @Test
    void aCopyOfTheTrustAnchorInTheCertificateValuesIsTreatedAsDssTreatsIt() throws Exception {
        byte[] root = Tokens.rootCaWithMalformedSubjectKeyIdentifier();
        assertThrows(IllegalArgumentException.class, () -> CertificateChecks.decode(DSSUtils.loadCertificate(root)));
        byte[] tsa = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        assertAsDssAlone(Tokens.withCertificateValues(Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")),
                tsa, root), "cert-values-root-copy");
    }

    /**
     * pki/tsa in certificateValues with 1,000 self-issued certificates of
     * the name and key of pki/ca-ecdsa, each of which verifies the others:
     * the checks of the tool must not make the run much slower than DSS
     * alone, at most six times as long with a second of margin (issue #72).
     */
    @Test
    void manySelfIssuedCertificatesOfOneNameAndKeyDoNotMakeTheChecksSlowerThanDss() throws Exception {
        byte[] valid = Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"));
        byte[] tsa = Pem.decode(Files.readString(CORPUS.resolve("pki/tsa.pem")));
        List<byte[]> values = new ArrayList<>(List.of(tsa));
        values.addAll(Tokens.selfIssuedWithTheNameAndKeyOfCaEcdsa(1000));
        byte[] token = Tokens.withCertificateValues(valid, values.toArray(byte[][]::new));
        copiesRun(Tokens.withCertificateValues(valid, tsa), "self-issued-warm-up");
        long start = System.nanoTime();
        MutationTest.RawResult alone = MutationTest.rawDss(MutationTest.Setup.corpus(token));
        long dss = System.nanoTime() - start;
        assertNull(alone.failure());
        Path file = Files.write(temp.resolve("self-issued.tst"), token);
        Path result = temp.resolve("self-issued");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, file.toString());
        start = System.nanoTime();
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        long tool = System.nanoTime() - start;
        String timings = "1000 self-issued: tool " + tool / 1_000_000 + " ms, DSS alone " + dss / 1_000_000 + " ms";
        System.out.println(timings);
        Map<String, Object> summary = summary(result);
        assertEquals("validated", summary.get("result"), summary.toString());
        assertEquals(alone.indication(), summary.get("indication") + " " + summary.get("sub-indication"));
        assertTrue(tool < 6 * dss + 1_000_000_000L, timings);
    }

    /** Asserts that the tool rejects the token, and that DSS alone fails on it at the same stage. */
    private void assertTokenRejected(byte[] content, String name) throws Exception {
        Path token = Files.write(temp.resolve(name + ".tst"), content);
        Path result = temp.resolve(name);
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertRejected(args, result, "--timestamp", token.toString());
        String message = (String) summary(result).get("message");
        assertNull(MutationTest.crossCheckToken(content, message), message);
    }

    @Test
    void aTokenWithoutEncapsulatedContentIsRejected() throws Exception {
        assertTokenRejected(Tokens.withoutEncapsulatedContent(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))), "no-content");
    }

    @Test
    void aTokenWithAnEmptySigningCertificateHashIsRejected() throws Exception {
        assertTokenRejected(Tokens.withEmptySigningCertificateHash(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))), "empty-cert-hash");
    }

    @Test
    void aTokenWithASigningCertificateHashThatDssCannotComputeIsRejected() throws Exception {
        assertTokenRejected(Tokens.withShake128SigningCertificateHash(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))), "shake-cert-hash");
    }

    @Test
    void anOcspResponseHoldingACertificateWithAWrongEncodingIsRejected() throws Exception {
        // Found by mutation: Bouncy Castle fails with "unexpected explicit encoding" on the certificate.
        byte[] response = OcspResponses.forTsa();
        response[332] = 1;
        Path file = Files.write(temp.resolve("explicit.ocsp"), response);
        Path result = temp.resolve("explicit");
        assertRejected(arguments("valid", "--ocsp", file.toString(), "--out", result.toString()), result,
                "--ocsp", file.toString());
    }

    @Test
    void aCrlDeclaringALargeLengthIsRejectedWithoutAllocatingIt() throws Exception {
        byte[] crl = Files.readAllBytes(CORPUS.resolve("crl/root-ca.crl"));
        crl[103] = (byte) 0x84;
        Path file = Files.write(temp.resolve("large-length.crl"), crl);
        Path result = temp.resolve("large-length");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf(corpus("crl/root-ca.crl")), file.toString());
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long before = threads.getCurrentThreadAllocatedBytes();
        assertRejected(args, result, "--crl", file.toString());
        long allocated = threads.getCurrentThreadAllocatedBytes() - before;
        assertTrue(allocated < 64L * 1024 * 1024, "allocated " + allocated + " bytes");
    }

    private void assertCrlUsed(byte[] crl, String name) throws Exception {
        Path file = Files.write(temp.resolve(name + ".crl"), crl);
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"));
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), file.toString());
        Path result = temp.resolve(name);
        args.addAll(List.of("--out", result.toString()));
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    @Test
    void aCrlWhoseLastSignatureOctetIsMissingIsUsedAsDssUsesIt() throws Exception {
        // The signature ends with a zero octet; DSS reads the short CRL as if the zero were there.
        byte[] crl = Crls.caEcdsaSignatureEndingInZero();
        assertCrlUsed(Arrays.copyOf(crl, crl.length - 1), "short");
    }

    @Test
    void aCrlWithAnIndefiniteOuterLengthIsUsedAsDssUsesIt() throws Exception {
        byte[] original = Files.readAllBytes(CORPUS.resolve("crl/ca-ecdsa.crl"));
        byte[] crl = new byte[original.length - 2];
        crl[0] = 0x30;
        crl[1] = (byte) 0x80;
        System.arraycopy(original, 4, crl, 2, original.length - 4);
        assertCrlUsed(crl, "outer-indefinite");
    }

    private static Attribute signingCertificate(ESSCertID... ids) {
        return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(
                new DERSequence(new DERSequence(ids))));
    }

    private static Attribute signingCertificateV2(ESSCertIDv2... ids) {
        return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(
                new SigningCertificateV2(ids)));
    }

    private byte[] resigned(Attribute... attributes) throws Exception {
        return Tokens.resignedWithSigningCertificates(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")), attributes);
    }

    @Test
    void anEmptyHashAfterTheMatchingReferenceIsUsedAsDssUsesIt() throws Exception {
        ESSCertID empty = new ESSCertID(new byte[0], Tokens.tsaIssuerSerial());
        Path token = Files.write(temp.resolve("ok-then-empty.tst"),
                resigned(signingCertificate(Tokens.tsaCertId(), empty)));
        Path result = temp.resolve("ok-then-empty");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
    }

    @Test
    void signingCertificateReferencesOnWhichDssFailsAreRejected() throws Exception {
        ESSCertID empty = new ESSCertID(new byte[0], Tokens.tsaIssuerSerial());
        ESSCertID emptyWithoutIssuer = new ESSCertID(new byte[0]);
        ESSCertIDv2 shake = new ESSCertIDv2(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128),
                Tokens.tsaCertIdV2().getCertHash(), Tokens.tsaIssuerSerial());
        assertTokenRejected(resigned(signingCertificate(empty, Tokens.tsaCertId())), "empty-then-ok");
        assertTokenRejected(resigned(signingCertificateV2(Tokens.tsaCertIdV2()), signingCertificate(empty)),
                "v2-ok-and-v1-empty");
        assertTokenRejected(resigned(signingCertificate(Tokens.tsaCertId(), emptyWithoutIssuer)),
                "ok-then-empty-without-issuer");
        assertTokenRejected(resigned(signingCertificateV2(Tokens.tsaCertIdV2(), shake)), "v2-ok-then-shake");
        assertTokenRejected(resigned(signingCertificate(Tokens.tsaCertId()), signingCertificateV2(shake)),
                "v1-ok-and-v2-shake");
    }

    @Test
    void cmsStructuresWithMissingMembersAreRejected() throws Exception {
        for (String hex : List.of(
                // ContentInfo of type signedData with an empty SignedData.
                "300f06092a864886f70d010702a0023000",
                // ContentInfo of type signedData without content.
                "300b06092a864886f70d010702",
                // SignedData with its version only.
                "301206092a864886f70d010702a00530030201 03".replace(" ", ""),
                // SignedData with version and digestAlgorithms only.
                "301406092a864886f70d010702a007300502010331 00".replace(" ", ""),
                // SignedData without signerInfos.
                "302306092a864886f70d010702a01630140201033100300d060b2a864886f70d0109100104")) {
            assertTokenRejected(HexFormat.of().parseHex(hex), "cms-" + hex.length());
        }
    }

    @Test
    void aSignedCrlWithAnIndefiniteLengthInItsExtensionsIsUsedAsDssUsesIt() throws Exception {
        assertCrlUsed(Crls.caEcdsaWithIndefiniteExtensions(), "indefinite-extensions");
    }

    @Test
    void aSignedCrlWithAnIndefiniteLengthEntryIsRejected() throws Exception {
        Path file = Files.write(temp.resolve("indefinite-entry.crl"), Crls.caEcdsaWithIndefiniteEntry());
        Path result = temp.resolve("indefinite-entry");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf(corpus("crl/ca-ecdsa.crl")), file.toString());
        assertRejected(args, result, "--crl", file.toString());
    }

    /**
     * Every element of crl/ca-ecdsa in turn declares a length just under
     * 64 MiB. In a JVM with a heap of 128 MiB, every run must end with exit
     * code 0: the CRL is rejected before DSS reads it, or DSS reads it within
     * the heap.
     */
    @Test
    void largeLengthsInEveryElementOfACrlEndWithinASmallHeap() throws Exception {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx128m",
                "-cp", System.getProperty("java.class.path"), HeapProbe.class.getName()));
        for (int offset : Crls.caEcdsaElementOffsets()) {
            command.add(Files.write(temp.resolve("large-" + offset + ".crl"),
                    Crls.caEcdsaWithLength(offset, 64L * 1024 * 1024 - 1)).toString());
        }
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);
    }

    @Test
    void aSigningCertificateV2ListIsReadUpToItsFirstUnknownAlgorithmAsDssReadsIt() throws Exception {
        ESSCertIDv2 match = Tokens.tsaCertIdV2();
        ESSCertIDv2 unknown = new ESSCertIDv2(new AlgorithmIdentifier(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.32473.99")), match.getCertHash(),
                match.getIssuerSerial());
        ESSCertIDv2 shake = new ESSCertIDv2(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128),
                match.getCertHash(), match.getIssuerSerial());
        Path token = Files.write(temp.resolve("unknown-shake-match.tst"),
                resigned(signingCertificateV2(unknown, shake, match)));
        Path result = temp.resolve("unknown-shake-match");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"), "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, "PASSED", null);
        assertTokenRejected(resigned(signingCertificateV2(shake, unknown, match)), "shake-unknown-match");
    }

    @Test
    void aCertificateGivenAsAnOcspResponseIsRejected() throws Exception {
        for (String file : List.of(corpus("pki/tsa.pem"), derCertificate().toString())) {
            Path result = temp.resolve("certificate-as-ocsp-" + file.length());
            assertRejected(arguments("valid", "--ocsp", file, "--out", result.toString()), result, "--ocsp", file);
        }
    }

    @Test
    void aTruncatedOcspResponseIsRejected() throws Exception {
        byte[] response = OcspResponses.wellFormed();
        Path file = Files.write(temp.resolve("truncated.ocsp"), Arrays.copyOf(response, response.length - 10));
        Path result = temp.resolve("truncated-ocsp");
        assertRejected(arguments("valid", "--ocsp", file.toString(), "--out", result.toString()), result,
                "--ocsp", file.toString());
    }

    @Test
    void anOcspResponseWithAMalformedSingleResponseIsRejected() throws Exception {
        Path file = Files.write(temp.resolve("malformed.ocsp"), OcspResponses.malformedSingleResponse());
        Path result = temp.resolve("malformed-ocsp");
        assertRejected(arguments("valid", "--ocsp", file.toString(), "--out", result.toString()), result,
                "--ocsp", file.toString());
    }

    @Test
    void aTokenWithAnUnknownImprintAlgorithmIsRejected() throws Exception {
        Path token = Files.write(temp.resolve("unknown-imprint.tst"), Tokens.withUnknownImprintAlgorithm(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))));
        List<List<String>> variants = List.of(
                List.of("--data", corpus("timestamps/content.txt")),
                List.of(),
                List.of("--digest", "00".repeat(32), "--digest-algorithm", "SHA256"));
        for (int i = 0; i < variants.size(); i++) {
            Path result = temp.resolve("unknown-imprint-" + i);
            List<String> args = arguments("valid", variants.get(i).toArray(String[]::new));
            args.set(args.indexOf("--timestamp") + 1, token.toString());
            args.addAll(List.of("--out", result.toString()));
            assertRejected(args, result, "--timestamp", token.toString());
            assertTrue(((String) summary(result).get("message")).contains(Tokens.UNKNOWN_IMPRINT_OID),
                    summary(result).toString());
        }
    }

    @Test
    void aTokenWithAMalformedSignatureIsRejected() throws Exception {
        Path token = Files.write(temp.resolve("malformed-signature.tst"), Tokens.withMalformedSignature(
                Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst"))));
        Path result = temp.resolve("malformed-signature");
        List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, token.toString());
        assertRejected(args, result, "--timestamp", token.toString());
    }

    /**
     * One mutation of a corpus token per kind of failure that the mutation
     * test found, each of which made DSS fail during the validation, before
     * the token was checked up front. The offsets refer to the committed
     * corpus files.
     */
    @Test
    void tokensOnWhichDssFailsLateAreRejected() throws Exception {
        record Case(String token, int offset, int value, String message) {
        }
        List<Case> cases = List.of(
                // The OID id-ecPublicKey of the certificate becomes unknown: its key cannot be decoded.
                new Case("gen-time-after-validation-time", 373, 2, "a certificate in the token cannot be decoded"),
                // A byte of a UTF8String in the subject name becomes invalid UTF-8.
                new Case("valid", 348, 211, "a certificate in the token cannot be decoded"),
                // The authority key identifier extension gets an illegal tag.
                new Case("imprint-mismatch", 507, 74, "a certificate in the token cannot be decoded"),
                // The signature algorithm of the signer becomes an unknown OID.
                new Case("gen-time-after-validation-time", 1178, 32, "the signature of the token cannot be decoded"));
        for (Case c : cases) {
            byte[] content = Files.readAllBytes(CORPUS.resolve("timestamps/" + c.token() + ".tst"));
            content[c.offset()] = (byte) c.value();
            Path token = Files.write(temp.resolve(c.token() + "-" + c.offset() + ".tst"), content);
            Path result = temp.resolve("late-" + c.token() + "-" + c.offset());
            List<String> args = arguments("valid", "--data", corpus("timestamps/content.txt"),
                    "--out", result.toString());
            args.set(args.indexOf("--timestamp") + 1, token.toString());
            assertRejected(args, result, "--timestamp", token.toString());
            assertTrue(((String) summary(result).get("message")).startsWith(c.message()), summary(result).toString());
        }
    }

    /**
     * Bouncy Castle provides RIPEMD-160, not the JVM. DSS registers it when
     * it starts, which a fresh process has not done yet when the options are
     * checked, so this runs the tool in a new JVM.
     */
    @Test
    void aDigestAlgorithmThatOnlyBouncyCastleProvidesIsKnownInAFreshProcess() throws Exception {
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        command.addAll(arguments("valid", "--digest", "00".repeat(20), "--digest-algorithm", "RIPEMD160",
                "--out", temp.resolve("ripemd").toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.USAGE, process.waitFor(), output);
        assertFalse(output.contains("not available"), output);
        assertTrue(output.contains("differs from the algorithm of the message imprint"), output);
    }

    @Test
    void aMissingFileIsAToolFailure() {
        Path result = temp.resolve("missing");
        List<String> args = arguments("valid", "--out", result.toString());
        args.set(args.indexOf("--timestamp") + 1, temp.resolve("absent.tst").toString());
        assertEquals(ExitCodes.FAILURE, run(args));
        assertTrue(stderr().contains("absent.tst"), stderr());
        assertFalse(Files.exists(result.resolve("summary.json")));
    }

    @Test
    void aMissingDataFileIsAToolFailure() {
        Path result = temp.resolve("missing-data");
        assertEquals(ExitCodes.FAILURE, run(arguments("valid",
                "--data", temp.resolve("absent.txt").toString(), "--out", result.toString())));
        assertFalse(Files.exists(result.resolve("summary.json")));
    }

    @Test
    void aNonEmptyOutputDirectoryIsAToolFailure() throws IOException {
        Path result = Files.createDirectories(temp.resolve("used"));
        Files.writeString(result.resolve("old.txt"), "old");
        assertEquals(ExitCodes.FAILURE, run(arguments("valid", "--out", result.toString())));
        assertEquals(List.of("old.txt"), files(result));
    }

    @Test
    void anOutputPathThatIsAFileIsAToolFailure() throws IOException {
        Path result = Files.writeString(temp.resolve("file"), "x");
        assertEquals(ExitCodes.FAILURE, run(arguments("valid", "--out", result.toString())));
    }

    @Test
    void anEmptyOutputDirectoryIsUsed() throws Exception {
        Path result = Files.createDirectories(temp.resolve("empty"));
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--data", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        assertValidated(result, "PASSED", null);
    }

    // Usage errors.

    @Test
    void dataAndDigestAreMutuallyExclusive() throws NoSuchAlgorithmException {
        String digest = sha256Hex(new byte[0]);
        assertEquals(ExitCodes.USAGE, run(arguments("valid", "--data", corpus("timestamps/content.txt"),
                "--digest", digest, "--digest-algorithm", "SHA256", "--out", temp.resolve("x").toString())));
        assertTrue(stderr().contains("--data"), stderr());
        assertFalse(Files.exists(temp.resolve("x")));
    }

    @Test
    void aDigestNeedsItsAlgorithmAndTheReverse() throws NoSuchAlgorithmException {
        String digest = sha256Hex(new byte[0]);
        assertEquals(ExitCodes.USAGE, run(arguments("valid", "--digest", digest,
                "--out", temp.resolve("x").toString())));
        assertEquals(ExitCodes.USAGE, run(arguments("valid", "--digest-algorithm", "SHA256",
                "--out", temp.resolve("y").toString())));
    }

    @Test
    void requiredOptionsMustBeGiven() {
        List<String> complete = arguments("valid", "--out", temp.resolve("x").toString());
        for (String option : List.of("--timestamp", "--trust-anchor", "--validation-time", "--out")) {
            err.reset();
            assertEquals(ExitCodes.USAGE, run(without(complete, option)), option);
            assertTrue(stderr().contains(option), stderr());
        }
    }

    @Test
    void anInvalidDigestIsAUsageError() {
        for (String digest : List.of("xyz", "abc", "00".repeat(31), "00".repeat(33))) {
            assertEquals(ExitCodes.USAGE, run(arguments("valid", "--digest", digest, "--digest-algorithm", "SHA256",
                    "--out", temp.resolve("x").toString())), digest);
        }
    }

    @Test
    void anUnknownDigestAlgorithmIsAUsageError() {
        assertEquals(ExitCodes.USAGE, run(arguments("valid", "--digest", "00".repeat(32),
                "--digest-algorithm", "SHA-999", "--out", temp.resolve("x").toString())));
    }

    @Test
    void aDigestAlgorithmOtherThanTheTokensIsAUsageError() {
        Path result = temp.resolve("x");
        assertEquals(ExitCodes.USAGE, run(arguments("valid", "--digest", "00".repeat(64),
                "--digest-algorithm", "SHA512", "--out", result.toString())));
        assertTrue(stderr().contains("SHA256"), stderr());
        assertFalse(Files.exists(result.resolve("summary.json")));
    }

    @Test
    void theSummaryNamesNoSubIndicationAsNull() throws Exception {
        Path result = temp.resolve("null");
        assertEquals(ExitCodes.SUCCESS, run(arguments("valid",
                "--data", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertTrue(summary.containsKey("sub-indication"));
        assertNull(summary.get("sub-indication"));
    }
}
