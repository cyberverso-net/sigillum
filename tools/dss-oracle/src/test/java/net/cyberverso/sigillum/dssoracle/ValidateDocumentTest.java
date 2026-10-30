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
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests of the validate-document mode on CAdES, PAdES and JAdES documents
 * that the tests sign with DSS and the keys of the test PKI, at the planned
 * signing time and the validation time of the corpus.
 */
class ValidateDocumentTest {

    private static final Path CORPUS = Path.of("..", "..", "testdata");
    private static final String VALIDATION_TIME = "2030-01-15T10:00:00Z";
    private static final String SIGNING_TIME = "2029-12-16T10:00:00Z";
    private static final List<String> REPORTS = List.of(
            "diagnostic-data.xml", "detailed-report.xml", "simple-report.xml", "etsi-validation-report.xml");
    /** The name of the default validation policy of DSS 6.5.1. */
    private static final String DEFAULT_POLICY = "QES AES/QC AES TL based";

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

    private Path write(String name, byte[] content) throws IOException {
        return Files.write(temp.resolve(name), content);
    }

    /** The arguments for a document with the chain and CRLs of pki/signer-p256, without --out. */
    private static List<String> arguments(Path document, String... extra) {
        List<String> args = new ArrayList<>(List.of(
                "validate-document",
                "--document", document.toString(),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--certificate", corpus("pki/ca-ecdsa.pem"),
                "--crl", corpus("crl/ca-ecdsa.crl"),
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

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> signatures(Path directory) throws IOException {
        return (List<Map<String, Object>>) member(summary(directory), "details").get("signatures");
    }

    private static List<String> files(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    /** Checks the identity of the oracle that every summary records. */
    static void assertOracle(Map<String, Object> summary) {
        @SuppressWarnings("unchecked")
        Map<String, Object> oracle = (Map<String, Object>) summary.get("oracle");
        assertEquals(List.of("tool-version", "dss-version", "pdf-backend", "pdf-backend-version"),
                List.copyOf(oracle.keySet()), summary.toString());
        assertEquals("0.0.0", oracle.get("tool-version"));
        assertEquals("6.5.1", oracle.get("dss-version"));
        assertEquals("dss-pades-pdfbox", oracle.get("pdf-backend"));
        assertEquals("3.0.8", oracle.get("pdf-backend-version"));
    }

    /**
     * Checks a validated run against DSS alone, given the same inputs: the
     * simple report has the same content, and summary.json gives every
     * signature of it, in its order, with the values that DSS alone reports.
     * The top-level indication is that of the only signature, or null.
     *
     * @return the signatures of the summary
     */
    private List<Map<String, Object>> assertAsDssAlone(Path directory, DssAlone.Inputs inputs) throws Exception {
        Map<String, Object> summary = summary(directory);
        assertEquals(3L, summary.get("format-version"));
        assertOracle(summary);
        assertEquals("validate-document", summary.get("mode"));
        assertEquals(VALIDATION_TIME, summary.get("validation-time"));
        assertEquals("validated", summary.get("result"), summary.toString());
        List<String> expected = new ArrayList<>(REPORTS);
        expected.add("summary.json");
        expected.sort(null);
        assertEquals(expected, files(directory));
        for (String report : REPORTS) {
            assertFalse(XmlContent.of(directory.resolve(report)).isEmpty(), report);
        }
        Reports reports = DssAlone.validate(inputs);
        Path alone = Files.writeString(temp.resolve("alone-" + directory.getFileName() + ".xml"),
                reports.getXmlSimpleReport());
        assertEquals(XmlContent.of(alone), XmlContent.of(directory.resolve("simple-report.xml")));
        SimpleReport simple = reports.getSimpleReport();
        List<String> ids = simple.getSignatureIdList();
        List<Map<String, Object>> signatures = signatures(directory);
        assertEquals(ids, signatures.stream().map(signature -> signature.get("signature-id")).toList());
        for (Map<String, Object> signature : signatures) {
            String id = (String) signature.get("signature-id");
            SignatureWrapper wrapper = reports.getDiagnosticData().getSignatureById(id);
            assertEquals(simple.getIndication(id).name(), signature.get("indication"), id);
            assertEquals(simple.getSubIndication(id) == null ? null : simple.getSubIndication(id).name(),
                    signature.get("sub-indication"), id);
            assertEquals(wrapper.getSignatureFormat().toString(), signature.get("level"), id);
            assertEquals(wrapper.getSignatureFormat().getSignatureForm().name(), signature.get("format"), id);
            assertEquals(wrapper.getClaimedSigningTime().toInstant().toString(), signature.get("signing-time"), id);
            assertEquals(simple.getBestSignatureTime(id).toInstant().toString(), signature.get("best-signature-time"),
                    id);
            assertEquals(simple.getAdESValidationErrors(id).size(), ((List<?>) signature.get("errors")).size(), id);
            assertEquals(simple.getAdESValidationWarnings(id).size(), ((List<?>) signature.get("warnings")).size(),
                    id);
        }
        Map<String, Object> only = signatures.size() == 1 ? signatures.get(0) : null;
        assertEquals(only == null ? null : only.get("indication"), summary.get("indication"), summary.toString());
        assertEquals(only == null ? null : only.get("sub-indication"), summary.get("sub-indication"),
                summary.toString());
        return signatures;
    }

    /** Checks a validated run with one signature against DSS alone, and returns its signature. */
    private Map<String, Object> assertValidated(Path directory, DssAlone.Inputs inputs, String indication,
            String subIndication) throws Exception {
        List<Map<String, Object>> signatures = assertAsDssAlone(directory, inputs);
        assertEquals(1, signatures.size(), signatures.toString());
        Map<String, Object> signature = signatures.get(0);
        assertEquals(indication, signature.get("indication"), signature.toString());
        assertEquals(subIndication, signature.get("sub-indication"), signature.toString());
        assertTrue(signature.get("signature-id") instanceof String id && id.startsWith("S-"), signature.toString());
        assertTrue(Files.readString(directory.resolve("simple-report.xml"))
                .contains((String) signature.get("signature-id")), signature.toString());
        return signature;
    }

    private static void assertSignature(Map<String, Object> signature, String format, String level) {
        assertEquals(format, signature.get("format"), signature.toString());
        assertEquals(level, signature.get("level"), signature.toString());
        assertEquals(SIGNING_TIME, signature.get("signing-time"), signature.toString());
        // Without a timestamp, DSS has no proof of existence before the validation time.
        assertEquals(VALIDATION_TIME, signature.get("best-signature-time"), signature.toString());
        assertTrue(signature.get("errors") instanceof List<?> errors && errors.isEmpty(), signature.toString());
        assertTrue(signature.get("warnings") instanceof List<?>, signature.toString());
    }

    // Acceptance criteria 1 and 2: CAdES, PAdES and JAdES documents are validated and summarised.

    @Test
    void aCadesDocumentIsValidated() throws Exception {
        Path result = temp.resolve("cades");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.p7m", Documents.cades()),
                "--out", result.toString())), stderr());
        assertSignature(assertValidated(result, DssAlone.Inputs.of(Documents.cades(), "signed.p7m"),
                "TOTAL_PASSED", null), "CAdES", "CAdES-BASELINE-B");
        // ADR-0023: the aligned policy applies when --policy is absent.
        assertEquals("aligned-1", summary(result).get("policy"));
    }

    /**
     * An Ed25519 signature passes under the aligned policy, which accepts
     * Ed25519, and not under the default policy of DSS 6.5.1, which does not
     * (ADR-0023). The CRL of pki/ca-ed25519 is supplied for the chain.
     */
    @Test
    void anEd25519SignaturePassesUnderTheAlignedPolicyOnly() throws Exception {
        Path document = write("ed25519.p7m", Documents.cadesEd25519());
        Map<String, String> results = new java.util.LinkedHashMap<>();
        for (String policy : List.of("aligned", "default")) {
            Path result = temp.resolve("ed25519-" + policy);
            List<String> args = new ArrayList<>(List.of("validate-document", "--document", document.toString(),
                    "--trust-anchor", corpus("pki/root-ca.pem"), "--certificate", corpus("pki/ca-ed25519.pem"),
                    "--crl", corpus("crl/ca-ed25519.crl"), "--crl", corpus("crl/root-ca.crl"),
                    "--validation-time", VALIDATION_TIME, "--policy", policy, "--out", result.toString()));
            assertEquals(ExitCodes.SUCCESS, run(args), stderr());
            Map<String, Object> summary = summary(result);
            results.put(policy, summary.get("indication") + " " + summary.get("sub-indication"));
        }
        assertEquals("TOTAL_PASSED null", results.get("aligned"), results.toString());
        assertTrue(results.get("default").startsWith("INDETERMINATE"), results.toString());
    }

    @Test
    void theDefaultPolicyOfDssIsSelectedByName() throws Exception {
        Path result = temp.resolve("default");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.p7m", Documents.cades()),
                "--policy", "default", "--out", result.toString())), stderr());
        assertValidated(result, DssAlone.Inputs.of(Documents.cades(), "signed.p7m")
                .withNamedPolicy(OraclePolicy.DEFAULT), "TOTAL_PASSED", null);
        assertEquals("default", summary(result).get("policy"));
        assertTrue(Files.readString(result.resolve("simple-report.xml")).contains(DEFAULT_POLICY));
    }

    @Test
    void theAlignedPolicyIsSelectedByNameAsWithoutTheOption() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        Path implicit = temp.resolve("aligned-implicit");
        Path named = temp.resolve("aligned-named");
        assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--out", implicit.toString())), stderr());
        assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--policy", "aligned", "--out", named.toString())),
                stderr());
        for (String file : List.of("summary.json", "diagnostic-data.xml", "detailed-report.xml",
                "simple-report.xml")) {
            assertTrue(Arrays.equals(Files.readAllBytes(implicit.resolve(file)),
                    Files.readAllBytes(named.resolve(file))), file);
        }
    }

    @Test
    void aPadesDocumentIsValidated() throws Exception {
        Path result = temp.resolve("pades");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.pdf", Documents.pades()),
                "--out", result.toString())), stderr());
        assertSignature(assertValidated(result, DssAlone.Inputs.of(Documents.pades(), "signed.pdf"),
                "TOTAL_PASSED", null), "PAdES", "PAdES-BASELINE-B");
    }

    @Test
    void aJadesDocumentIsValidated() throws Exception {
        Path result = temp.resolve("jades");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.jws", Documents.jades()),
                "--out", result.toString())), stderr());
        assertSignature(assertValidated(result, DssAlone.Inputs.of(Documents.jades(), "signed.jws"),
                "TOTAL_PASSED", null), "JAdES", "JAdES-BASELINE-B");
    }

    @Test
    void aJadesDocumentInTheJsonSerialisationIsValidated() throws Exception {
        Path result = temp.resolve("jades-json");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.json", Documents.jadesJson()),
                "--out", result.toString())), stderr());
        assertSignature(assertValidated(result, DssAlone.Inputs.of(Documents.jadesJson(), "signed.json"),
                "TOTAL_PASSED", null), "JAdES", "JAdES-BASELINE-B");
    }

    @Test
    void aDetachedSignatureIsValidatedWithItsContent() throws Exception {
        Path signature = write("detached.p7s", Documents.cadesDetached());
        Path result = temp.resolve("detached");
        assertEquals(ExitCodes.SUCCESS, run(arguments(signature,
                "--detached", write("content.txt", Documents.CONTENT).toString(),
                "--out", result.toString())), stderr());
        assertSignature(assertValidated(result, DssAlone.Inputs.of(Documents.cadesDetached(), "detached.p7s")
                .withDetached(Documents.CONTENT, "content.txt"), "TOTAL_PASSED", null), "CAdES", "CAdES-BASELINE-B");
    }

    @Test
    void aSignatureTimestampGivesTheBestSignatureTime() throws Exception {
        Path result = temp.resolve("cades-t");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed-t.p7m", Documents.cadesT()),
                "--out", result.toString())), stderr());
        Map<String, Object> signature = assertValidated(result,
                DssAlone.Inputs.of(Documents.cadesT(), "signed-t.p7m"), "TOTAL_PASSED", null);
        assertEquals("CAdES", signature.get("format"));
        assertEquals("CAdES-BASELINE-T", signature.get("level"));
        assertEquals(SIGNING_TIME, signature.get("signing-time"));
        assertEquals("2029-12-16T10:01:00Z", signature.get("best-signature-time"));
    }

    /**
     * A CAdES signature without its certificates is validated with its
     * signing certificate supplied with {@code --certificate}, which DSS
     * then takes as a candidate (issue #37).
     */
    @Test
    void aSigningCertificateSuppliedOfflineIsACandidate() throws Exception {
        byte[] document = Tokens.withoutCertificates(Documents.cades());
        Path result = temp.resolve("supplied-signer");
        List<String> args = arguments(write("bare.p7m", document), "--certificate", corpus("pki/signer-p256.pem"),
                "--out", result.toString());
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        assertValidated(result, DssAlone.Inputs.of(document, "bare.p7m").withCertificate(
                Files.readAllBytes(CORPUS.resolve("pki/signer-p256.pem"))), "TOTAL_PASSED", null);
    }

    /**
     * A certificate of a timestamp token that DSS does not use, here one
     * with a subject name that is not valid UTF-8, does not make the
     * document rejected (issue #37).
     */
    @Test
    void anUnusedMalformedCertificateOfATimestampIsIgnored() throws Exception {
        byte[] document = Documents.cadesTWithAnUnusedMalformedCertificate();
        Path result = temp.resolve("unused-malformed");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("unused.p7m", document), "--out", result.toString())),
                stderr());
        assertValidated(result, DssAlone.Inputs.of(document, "unused.p7m"), "TOTAL_PASSED", null);
    }

    @Test
    void aDetachedSignatureWithoutItsContentIsNotConclusive() throws Exception {
        Path result = temp.resolve("no-content");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("detached.p7s", Documents.cadesDetached()),
                "--out", result.toString())), stderr());
        assertValidated(result, DssAlone.Inputs.of(Documents.cadesDetached(), "detached.p7s"),
                "INDETERMINATE", "SIGNED_DATA_NOT_FOUND");
    }

    @Test
    void aDetachedSignatureWithOtherContentFails() throws Exception {
        Path result = temp.resolve("other-content");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("detached.p7s", Documents.cadesDetached()),
                "--detached", corpus("timestamps/content.txt"), "--out", result.toString())), stderr());
        assertValidated(result, DssAlone.Inputs.of(Documents.cadesDetached(), "detached.p7s").withDetached(
                Files.readAllBytes(CORPUS.resolve("timestamps/content.txt")), "content.txt"),
                "TOTAL_FAILED", "HASH_FAILURE");
    }

    @Test
    void theSuppliedSourcesAreTheOnlyOnes() throws Exception {
        // Without the CRLs, DSS has no revocation data for the signing certificate and retrieves none.
        Path result = temp.resolve("no-crl");
        List<String> args = arguments(write("signed.p7m", Documents.cades()), "--out", result.toString());
        for (String crl : List.of("crl/ca-ecdsa.crl", "crl/root-ca.crl")) {
            int index = args.indexOf(corpus(crl));
            args.subList(index - 1, index + 1).clear();
        }
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("validated", summary.get("result"));
        assertEquals("INDETERMINATE", summary.get("indication"), summary.toString());
        assertAsDssAlone(result, DssAlone.Inputs.of(Documents.cades(), "signed.p7m").withoutCrls());
    }

    /**
     * The signature policy identifier names a URL, and nothing may retrieve
     * it: a lookup would fail the run. This test is a regression guard. It
     * cannot fail without the signature policy provider that the mode sets,
     * because DSS 6.5.1 retrieves no policy document for CAdES, PAdES or
     * JAdES without one either: only its ASiC analysers create the provider
     * that has a data loader.
     */
    @Test
    void anExplicitPolicyIsNotRetrievedFromItsUrl() throws Exception {
        Path result = temp.resolve("policy-url");
        assertEquals(ExitCodes.SUCCESS, run(arguments(
                write("epes.p7m", Documents.cadesWithPolicyUrl("http://policy.example.invalid/policy.der")),
                "--out", result.toString())), stderr());
        assertEquals("validated", summary(result).get("result"));
    }

    // Acceptance criterion 1: the default policy of DSS, or the policy file given.

    @Test
    void theDefaultPolicyGivenAsAFileGivesTheSameResults() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        Path implicit = temp.resolve("implicit");
        Path explicit = temp.resolve("explicit");
        assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--policy", "default",
                "--out", implicit.toString())), stderr());
        Path file = write("constraint.xml", Documents.defaultPolicy());
        assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--policy", file.toString(),
                "--out", explicit.toString())), stderr());
        for (String report : List.of("diagnostic-data.xml", "detailed-report.xml", "simple-report.xml")) {
            assertTrue(Arrays.equals(Files.readAllBytes(implicit.resolve(report)),
                    Files.readAllBytes(explicit.resolve(report))), report);
        }
        // The summaries differ only in how the policy was given.
        Map<String, Object> first = summary(implicit);
        Map<String, Object> second = summary(explicit);
        assertEquals("default", first.remove("policy"));
        assertEquals(Map.of("file", file.toString(), "sha256", java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(Documents.defaultPolicy()))),
                second.remove("policy"));
        assertEquals(first, second);
    }

    @Test
    void aPolicyFileIsApplied() throws Exception {
        String policy = new String(Documents.defaultPolicy(), StandardCharsets.UTF_8)
                .replace("Name=\"" + DEFAULT_POLICY + "\"", "Name=\"sigillum test policy\"")
                .replaceFirst("(<AcceptableFormats Level=\"FAIL\">\\s*<Id>)\\*(</Id>)", "$1XAdES-BASELINE-B$2");
        Path file = write("policy.xml", policy.getBytes(StandardCharsets.UTF_8));
        Path result = temp.resolve("policy");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.p7m", Documents.cades()),
                "--policy", file.toString(), "--out", result.toString())), stderr());
        // The policy accepts only XAdES-BASELINE-B signatures.
        assertValidated(result, DssAlone.Inputs.of(Documents.cades(), "signed.p7m")
                .withPolicy(policy.getBytes(StandardCharsets.UTF_8)), "TOTAL_FAILED", "FORMAT_FAILURE");
        Map<String, Object> recorded = member(summary(result), "policy");
        assertEquals(file.toString(), recorded.get("file"));
        assertEquals(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(file))), recorded.get("sha256"));
        assertTrue(Files.readString(result.resolve("simple-report.xml")).contains("sigillum test policy"));
    }

    // Acceptance criterion 3: input that DSS cannot use is rejected; tool failures exit non-zero.

    private void assertRejected(List<String> args, Path result, String option, String file) throws IOException {
        assertEquals(ExitCodes.SUCCESS, run(args), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("rejected", summary.get("result"), summary.toString());
        assertEquals("validate-document", summary.get("mode"));
        assertOracle(summary);
        assertEquals(option, summary.get("input"));
        assertEquals(file, summary.get("file"));
        assertTrue(summary.get("message") instanceof String message && !message.isBlank(), summary.toString());
        assertFalse(summary.containsKey("indication"));
        assertEquals(List.of("summary.json"), files(result));
    }

    @Test
    void aFileThatIsNoSignedDocumentIsRejected() throws Exception {
        for (String file : List.of(corpus("timestamps/content.txt"), corpus("pki/root-ca.pem"))) {
            Path result = temp.resolve("not-signed-" + file.length());
            assertRejected(arguments(Path.of(file), "--out", result.toString()), result, "--document", file);
        }
    }

    @Test
    void truncatedDocumentsAreRejected() throws Exception {
        for (Map.Entry<String, byte[]> entry : Map.of("p7m", Documents.cades(), "jws", Documents.jades())
                .entrySet()) {
            byte[] content = entry.getValue();
            Path file = write("truncated." + entry.getKey(), Arrays.copyOf(content, content.length / 2));
            Path result = temp.resolve("truncated-" + entry.getKey());
            assertRejected(arguments(file, "--out", result.toString()), result, "--document", file.toString());
        }
    }

    @Test
    void anUnparsablePolicyIsRejected() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        for (String file : List.of(corpus("timestamps/content.txt"), corpus("manifest.toml"))) {
            Path result = temp.resolve("policy-" + file.length());
            assertRejected(arguments(document, "--policy", file, "--out", result.toString()), result,
                    "--policy", file);
        }
    }

    /**
     * A policy whose cryptographic constraints have a date format that is
     * not a pattern loads, and DSS fails on it only when the validation
     * reads those constraints. The tool must reject the policy exactly when
     * DSS alone fails with it, for each place of the constraints and for
     * documents that use different parts of the policy.
     */
    @Test
    void aPolicyWithABadDateFormatIsRejectedExactlyWhenDssFailsOnIt() throws Exception {
        Map<String, byte[]> documents = new java.util.LinkedHashMap<>();
        documents.put("signed.p7m", Documents.cades());
        documents.put("signed-t.p7m", Documents.cadesT());
        documents.put("unsigned.pdf", Documents.pdf());
        List<String> outcomes = new ArrayList<>();
        List<String> mismatches = new ArrayList<>();
        int rejections = 0;
        int validations = 0;
        for (int place = 0; place <= 13; place++) {
            Path policy = write("bad-format-" + place + ".xml", Documents.policyWithBadDateFormat(place));
            for (Map.Entry<String, byte[]> document : documents.entrySet()) {
                Path result = temp.resolve("bad-format-" + place + "-" + document.getKey());
                err.reset();
                assertEquals(ExitCodes.SUCCESS, run(arguments(write(document.getKey(), document.getValue()),
                        "--policy", policy.toString(), "--out", result.toString())),
                        place + " " + document.getKey() + ": " + stderr());
                Object outcome = summary(result).get("result");
                Throwable dss = DssAlone.failure(DssAlone.Inputs.of(document.getValue(), document.getKey())
                        .withPolicy(Files.readAllBytes(policy)));
                String expected = dss == null ? "validated" : "rejected";
                String line = place + " " + document.getKey() + " " + outcome + " (DSS alone: " + dss + ")";
                outcomes.add(line);
                if (!expected.equals(outcome)) {
                    mismatches.add(line);
                }
                if (dss == null) {
                    validations++;
                } else {
                    rejections++;
                    assertEquals("--policy", summary(result).get("input"), line);
                }
            }
        }
        assertTrue(mismatches.isEmpty(), "Mismatches:\n" + String.join("\n", mismatches));
        // Both outcomes occur, so the comparison is not vacuous.
        assertTrue(rejections > 0 && validations > 0, String.join("\n", outcomes));
    }

    @Test
    void anUnsignedPdfIsValidatedWithAPolicyWhoseGlobalDateFormatIsBad() throws Exception {
        Path policy = write("bad-global.xml", Documents.policyWithBadDateFormat(0));
        Path result = temp.resolve("unsigned-bad-global");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("unsigned.pdf", Documents.pdf()),
                "--policy", policy.toString(), "--out", result.toString())), stderr());
        assertEquals("validated", summary(result).get("result"), summary(result).toString());
        assertTrue(signatures(result).isEmpty());
        assertNull(DssAlone.failure(DssAlone.Inputs.of(Documents.pdf(), "unsigned.pdf")
                .withPolicy(Documents.policyWithBadDateFormat(0))));
    }

    // JSON nested beyond the limit of the JSON schema validator of DSS.

    @Test
    void jsonNestedBeyondTheLimitOfDssIsRejected() throws Exception {
        String deep = Documents.nestedHeader(JsonDepth.MAX_DEPTH);
        String encoded = Documents.base64url(deep);
        Map<String, byte[]> documents = new java.util.LinkedHashMap<>();
        documents.put("header.json", Documents.jwsWithNestedHeader(JsonDepth.MAX_DEPTH));
        documents.put("compact.jws", Documents.compactJwsWithNestedHeader(JsonDepth.MAX_DEPTH));
        documents.put("signatures.json", Documents.jwsWithNestedSignatures(JsonDepth.MAX_DEPTH));
        // The general syntax, RFC 7515, section 7.2.1: the protected header of an element of signatures.
        documents.put("general.json", Documents.generalJws(encoded));
        // DSS decodes base64url leniently, skipping a character outside the alphabet.
        documents.put("lenient.json", Documents.generalJws(encoded.substring(0, 4) + "*" + encoded.substring(4)));
        // JSON escapes in the member name and in the value (RFC 8259, section 7).
        documents.put("escaped-name.json", ("{\"payload\":\"e30\",\"prot\\u0065cted\":\"" + encoded
                + "\",\"signature\":\"AAAA\"}").getBytes(StandardCharsets.US_ASCII));
        documents.put("escaped-value.json", ("{\"payload\":\"e30\",\"protected\":\"\\u00"
                + Integer.toHexString(encoded.charAt(0)) + encoded.substring(1) + "\",\"signature\":\"AAAA\"}")
                .getBytes(StandardCharsets.US_ASCII));
        // DSS parses an etsiU component inside the unprotected header, two levels deeper than the component.
        documents.put("etsiu.json", Documents.jadesJsonWithNestedEtsiU(JsonDepth.MAX_DEPTH - 2));
        // DSS accepts line breaks at the end of the compact serialisation.
        documents.put("compact-newline.jws", (encoded + ".e30.AAAA\n").getBytes(StandardCharsets.US_ASCII));
        for (Map.Entry<String, byte[]> entry : documents.entrySet()) {
            Path file = write(entry.getKey(), entry.getValue());
            Path result = temp.resolve("deep-" + entry.getKey());
            assertRejected(arguments(file, "--out", result.toString()), result, "--document", file.toString());
            assertTrue(((String) summary(result).get("message")).contains("100000"), summary(result).toString());
            Throwable dss = DssAlone.failure(DssAlone.Inputs.of(entry.getValue(), entry.getKey()));
            assertTrue(dss != null && dss.getClass().getSimpleName().equals("TooDeeplyNestedValueException"),
                    entry.getKey() + ": " + dss);
        }
    }

    /**
     * A member named {@code protected} that is not a JWS Protected Header,
     * here inside an extension of the unprotected header, is not decoded:
     * DSS does not parse it, and the document is validated however deep its
     * decoded value is (issue #37).
     */
    @Test
    void aMemberNamedProtectedElsewhereIsNotTakenForAHeader() throws Exception {
        String json = new String(Documents.jadesJson(), StandardCharsets.US_ASCII);
        String extension = "\"header\":{\"foo\":{\"protected\":\""
                + Documents.base64url(Documents.nestedHeader(JsonDepth.MAX_DEPTH)) + "\"}},";
        byte[] document = ("{" + extension + json.substring(json.indexOf('{') + 1)).getBytes(StandardCharsets.US_ASCII);
        assertNull(DssAlone.failure(DssAlone.Inputs.of(document, "extension.json")));
        Path result = temp.resolve("extension");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("extension.json", document),
                "--out", result.toString())), stderr());
        assertAsDssAlone(result, DssAlone.Inputs.of(document, "extension.json"));
    }

    /**
     * Crafted JWS documents with JSON nested about as deep as DSS accepts,
     * at places that DSS parses or ignores: the tool must reject a document
     * exactly when DSS alone fails on it, and never fail itself.
     */
    @Test
    void craftedJwsAreRejectedExactlyWhenDssFailsOnThem() throws Exception {
        List<String> mismatches = new ArrayList<>();
        List<String> outcomes = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : Documents.craftedJws().entrySet()) {
            String name = entry.getKey() + ".json";
            Path result = temp.resolve("crafted-" + entry.getKey());
            err.reset();
            int code = run(arguments(write(name, entry.getValue()), "--out", result.toString()));
            Throwable dss = DssAlone.failure(DssAlone.Inputs.of(entry.getValue(), name));
            String expected = dss == null ? "validated" : "rejected";
            String outcome = code != ExitCodes.SUCCESS ? "exit " + code + ": " + stderr().strip()
                    : (String) summary(result).get("result");
            String line = entry.getKey() + ": " + outcome + " (DSS alone: " + dss + ")";
            outcomes.add(line);
            if (!expected.equals(outcome)
                    || "rejected".equals(outcome) && !"--document".equals(summary(result).get("input"))) {
                mismatches.add(line);
            }
        }
        assertTrue(mismatches.isEmpty(), "Mismatches:\n" + String.join("\n", mismatches)
                + "\nAll:\n" + String.join("\n", outcomes));
        // The probes of counter signatures make DSS alone fail; those of ignored members do not.
        for (String failing : List.of("csig-compact-b64", "csig-clear-obj", "csig-clear-compact", "csig-nested",
                "csig-string-json", "csig-general-clear-obj")) {
            assertTrue(outcomes.stream().anyMatch(line -> line.startsWith(failing + ": rejected")), failing);
        }
        for (String passing : List.of("etsiu-lenient", "etsiu-mixed", "general-plus-top",
                "general-plus-top-header", "csig-second-member-clear", "csig-second-member-b64",
                "skipped-entry-empty-signature", "skipped-entry-blank-signature", "skipped-entry-null-signature",
                "skipped-entry-without-signature", "skipped-entry-etsiu", "skipped-flattened-empty-signature")) {
            assertTrue(outcomes.stream().anyMatch(line -> line.startsWith(passing + ": validated")), passing);
        }
        // The walk itself finds the counter signatures, before DSS parses them.
        for (String counterSignature : List.of("csig-compact-b64", "csig-clear-obj", "csig-clear-compact",
                "csig-nested", "csig-string-json", "csig-general-clear-obj")) {
            String message = (String) summary(temp.resolve("crafted-" + counterSignature)).get("message");
            assertTrue(message.contains("a counter signature"), counterSignature + ": " + message);
        }
    }

    /**
     * Issue #72, comment case 13: a general JWS with the JAdES signature of
     * the tests, followed by an entry whose protected header is nested
     * deeper than DSS accepts and whose signature is empty. DSS skips that
     * entry and validates the signature, and so must the tool.
     */
    @Test
    void anEntryThatDssSkipsDoesNotRejectTheDocument() throws Exception {
        String json = new String(Documents.jadesJson(), StandardCharsets.US_ASCII);
        java.util.regex.Matcher payload = java.util.regex.Pattern.compile("\"payload\":\"([^\"]*)\"").matcher(json);
        java.util.regex.Matcher header = java.util.regex.Pattern.compile("\"protected\":\"([^\"]*)\"").matcher(json);
        java.util.regex.Matcher value = java.util.regex.Pattern.compile("\"signature\":\"([^\"]*)\"").matcher(json);
        assertTrue(payload.find() && header.find() && value.find(), json);
        String deep = Documents.base64url(Documents.nestedHeader(JsonDepth.MAX_DEPTH));
        byte[] document = ("{\"payload\":\"" + payload.group(1) + "\",\"signatures\":[{\"protected\":\""
                + header.group(1) + "\",\"signature\":\"" + value.group(1) + "\"},{\"protected\":\"" + deep
                + "\",\"signature\":\"\"}]}").getBytes(StandardCharsets.US_ASCII);
        DssAlone.Inputs inputs = DssAlone.Inputs.of(document, "skipped-entry.json");
        assertNull(DssAlone.failure(inputs));
        Path result = temp.resolve("skipped-entry");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("skipped-entry.json", document),
                "--out", result.toString())), stderr());
        List<Map<String, Object>> signatures = assertAsDssAlone(result, inputs);
        assertEquals(1, signatures.size());
        assertEquals("TOTAL_PASSED", signatures.get(0).get("indication"));
    }

    /**
     * Member names that spell the places the walk looks at, such as a root
     * member named {@code signatures/#/protected} or a header parameter
     * named {@code etsiU/#/cSig}, are not those places: DSS validates the
     * signature, and so must the tool (issue #37).
     */
    @Test
    void memberNamesThatSpellAPathAreNotThatPath() throws Exception {
        String json = new String(Documents.jadesJson(), StandardCharsets.US_ASCII);
        String deepHeader = Documents.base64url(Documents.nestedHeader(JsonDepth.MAX_DEPTH));
        Map<String, String> members = Map.of(
                "spelt-protected", "\"signatures/#/protected\":\"" + deepHeader + "\",",
                "spelt-csig", "\"header\":{\"etsiU/#/cSig\":\"" + deepHeader + ".e30.AAAA\"},",
                "spelt-etsiu", "\"header\":{\"etsiU/#\":\"" + deepHeader + "\"},");
        for (Map.Entry<String, String> member : members.entrySet()) {
            byte[] document = ("{" + member.getValue() + json.substring(json.indexOf('{') + 1))
                    .getBytes(StandardCharsets.US_ASCII);
            String name = member.getKey() + ".json";
            assertNull(DssAlone.failure(DssAlone.Inputs.of(document, name)), member.getKey());
            Path result = temp.resolve(member.getKey());
            err.reset();
            assertEquals(ExitCodes.SUCCESS, run(arguments(write(name, document), "--out", result.toString())),
                    member.getKey() + ": " + stderr());
            assertAsDssAlone(result, DssAlone.Inputs.of(document, name));
        }
    }

    /**
     * A standalone timestamp token given as the document, whose message
     * imprint uses SHAKE-128, which no provider computes: without detached
     * content DSS computes no imprint and validates it, with content it
     * fails. The tool must do as DSS alone (issue #37).
     */
    @Test
    void aTimestampWithAnImprintNoProviderComputesIsRejectedOnlyWithContent() throws Exception {
        // SHAKE-128 and SHAKE-256 (2.16.840.1.101.3.4.2.11 and 12), which no provider computes under those names.
        for (String oid : List.of("2.16.840.1.101.3.4.2.11", "2.16.840.1.101.3.4.2.12")) {
            byte[] token = Tokens.withImprintAlgorithm(
                    Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")), oid);
            String name = "shake-" + oid + ".tst";
            Path document = write(name, token);
            Path without = temp.resolve("without-" + oid);
            assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--out", without.toString())), stderr());
            assertNull(DssAlone.failure(DssAlone.Inputs.of(token, name)), oid);
            assertAsDssAlone(without, DssAlone.Inputs.of(token, name));
            byte[] content = Files.readAllBytes(CORPUS.resolve("timestamps/content.txt"));
            Path with = temp.resolve("with-" + oid);
            assertEquals(ExitCodes.SUCCESS, run(arguments(document, "--detached", corpus("timestamps/content.txt"),
                    "--out", with.toString())), stderr());
            assertTrue(DssAlone.failure(DssAlone.Inputs.of(token, name).withDetached(content, "content.txt"))
                    != null, oid);
            assertEquals("rejected", summary(with).get("result"), summary(with).toString());
            assertEquals("--document", summary(with).get("input"));
        }
    }


    @Test
    void jsonNestedUpToTheLimitOfDssIsValidated() throws Exception {
        // An etsiU component of this depth is, with the header and the etsiU array, at the limit.
        byte[] etsiU = Documents.jadesJsonWithNestedEtsiU(JsonDepth.MAX_DEPTH - 3);
        assertNull(DssAlone.failure(DssAlone.Inputs.of(etsiU, "etsiu.json")));
        Path etsiUResult = temp.resolve("deep-ok-etsiu");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("etsiu.json", etsiU), "--out", etsiUResult.toString())),
                stderr());
        assertEquals("validated", summary(etsiUResult).get("result"), summary(etsiUResult).toString());
        Map<String, byte[]> documents = Map.of(
                "header.json", Documents.jwsWithNestedHeader(JsonDepth.MAX_DEPTH - 1),
                "compact.jws", Documents.compactJwsWithNestedHeader(JsonDepth.MAX_DEPTH - 1),
                "signatures.json", Documents.jwsWithNestedSignatures(JsonDepth.MAX_DEPTH - 1));
        for (Map.Entry<String, byte[]> entry : documents.entrySet()) {
            Path result = temp.resolve("deep-ok-" + entry.getKey());
            assertEquals(ExitCodes.SUCCESS, run(arguments(write(entry.getKey(), entry.getValue()),
                    "--out", result.toString())), stderr());
            assertEquals("validated", summary(result).get("result"), entry.getKey() + " " + summary(result));
        }
    }

    // PDF documents with revisions after a signature, which DSS compares by rendering their pages.

    @Test
    void twoSignaturesOfAPdfAreReportedInOrderWithoutATopLevelIndication() throws Exception {
        Path result = temp.resolve("two");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("twice.pdf", Documents.padesTwice()),
                "--out", result.toString())), stderr());
        List<Map<String, Object>> signatures = assertAsDssAlone(result,
                DssAlone.Inputs.of(Documents.padesTwice(), "twice.pdf"));
        assertEquals(2, signatures.size());
        assertEquals(List.of(SIGNING_TIME, "2029-12-16T11:00:00Z"),
                signatures.stream().map(signature -> (String) signature.get("signing-time")).sorted().toList());
        assertNull(summary(result).get("indication"));
        assertNull(summary(result).get("sub-indication"));
    }

    @Test
    void aPageChangedAfterTheSignatureIsCompared() throws Exception {
        byte[] changed = Documents.withPageSize(Documents.pades(), 600);
        Path result = temp.resolve("changed");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("changed.pdf", changed),
                "--out", result.toString())), stderr());
        assertAsDssAlone(result, DssAlone.Inputs.of(changed, "changed.pdf"));
    }

    @Test
    void aPageTooLargeToRenderInTheHeapIsAResourceLimit() throws Exception {
        // DSS renders the page of 40000 by 40000 units to compare the revisions; in a heap of 256 MiB the run
        // ends with the result resource-limit, not with a failure.
        Path document = write("large-page.pdf", Documents.withPageSize(Documents.pades(), 40000));
        Path result = temp.resolve("large-page");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx256m", "-XX:+UseSerialGC",
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        command.addAll(arguments(document, "--out", result.toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, process.waitFor(), output);
        Map<String, Object> summary = summary(result);
        assertEquals("resource-limit", summary.get("result"), summary.toString());
        assertEquals("heap", summary.get("limit"), summary.toString());
        Map<String, Object> limits = member(summary, "limits");
        assertTrue((Long) limits.get("heap-bytes") <= 256L * 1024 * 1024, limits.toString());
        assertEquals(ResourceLimits.STACK_BYTES, limits.get("stack-bytes"));
        assertEquals((long) ResourceLimits.DEFAULT_TIMEOUT_SECONDS, limits.get("timeout-seconds"));
        assertEquals(List.of("summary.json"), files(result));
    }

    /**
     * In a fresh JVM whose home directory is a temporary one, a PDF whose
     * page, changed after the signature, uses a font that it does not embed
     * makes DSS render it with a substitute font of the host. PDFBox must not
     * write its font cache to the home directory.
     */
    @Test
    void pdfboxWritesNoFontCacheToTheHomeDirectory() throws Exception {
        Path home = Files.createDirectories(temp.resolve("home"));
        Path document = write("text.pdf", Documents.withTextInAFontNotEmbedded(Documents.pades()));
        Path result = temp.resolve("text");
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Duser.home=" + home,
                "-cp", System.getProperty("java.class.path"), Main.class.getName()));
        command.addAll(arguments(document, "--out", result.toString()));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(ExitCodes.SUCCESS, process.waitFor(), output);
        assertEquals("validated", summary(result).get("result"), summary(result).toString());
        assertFalse(Files.exists(home.resolve(".pdfbox.cache")), files(home).toString());
    }

    @Test
    void pdfboxKeepsItsFontCacheInATemporaryDirectory() throws Exception {
        Path result = temp.resolve("font-cache");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("signed.pdf", Documents.pades()),
                "--out", result.toString())), stderr());
        String cache = System.getProperty("pdfbox.fontcache");
        assertTrue(cache != null && Path.of(cache).toRealPath()
                .startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()), String.valueOf(cache));
    }

    @Test
    void anXmlFileThatIsNoPolicyIsRejected() throws Exception {
        Path policy = write("other.xml", "<?xml version=\"1.0\"?><Other/>".getBytes(StandardCharsets.UTF_8));
        Path result = temp.resolve("other-xml");
        assertRejected(arguments(write("signed.p7m", Documents.cades()), "--policy", policy.toString(),
                "--out", result.toString()), result, "--policy", policy.toString());
    }

    @Test
    void unparsableSourcesAreRejected() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        for (String option : List.of("--certificate", "--crl", "--ocsp")) {
            Path result = temp.resolve("source" + option);
            assertRejected(arguments(document, option, corpus("timestamps/content.txt"), "--out", result.toString()),
                    result, option, corpus("timestamps/content.txt"));
        }
        Path result = temp.resolve("anchor");
        List<String> args = arguments(document, "--out", result.toString());
        args.set(args.indexOf("--trust-anchor") + 1, corpus("crl/root-ca.crl"));
        assertRejected(args, result, "--trust-anchor", corpus("crl/root-ca.crl"));
    }

    @Test
    void missingFilesAreToolFailures() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        for (String option : List.of("--document", "--detached", "--policy")) {
            Path result = temp.resolve("missing" + option);
            List<String> args = arguments(document, "--out", result.toString());
            Path absent = temp.resolve("absent" + option);
            if (option.equals("--document")) {
                args.set(args.indexOf(option) + 1, absent.toString());
            } else {
                args.addAll(List.of(option, absent.toString()));
            }
            err.reset();
            assertEquals(ExitCodes.FAILURE, run(args), option);
            assertTrue(stderr().contains(absent.getFileName().toString()), stderr());
            assertFalse(Files.exists(result.resolve("summary.json")));
        }
    }

    @Test
    void anOutputDirectoryThatIsNotEmptyIsAFailure() throws Exception {
        Path result = Files.createDirectories(temp.resolve("used"));
        Files.writeString(result.resolve("old.txt"), "old");
        assertEquals(ExitCodes.FAILURE, run(arguments(write("signed.p7m", Documents.cades()),
                "--out", result.toString())));
        assertEquals(List.of("old.txt"), files(result));
    }

    @Test
    void requiredOptionsAreUsageErrors() throws Exception {
        List<String> complete = arguments(write("signed.p7m", Documents.cades()),
                "--out", temp.resolve("usage").toString());
        for (String option : List.of("--document", "--trust-anchor", "--validation-time", "--out")) {
            List<String> args = new ArrayList<>(complete);
            int index = args.indexOf(option);
            args.subList(index, index + 2).clear();
            err.reset();
            assertEquals(ExitCodes.USAGE, run(args), option);
            assertTrue(stderr().contains(option + " is required"), stderr());
        }
        assertFalse(Files.exists(temp.resolve("usage")));
    }

    @Test
    void timestampOptionsAreUsageErrors() throws Exception {
        Path document = write("signed.p7m", Documents.cades());
        for (String option : List.of("--timestamp", "--data", "--digest", "--digest-algorithm")) {
            err.reset();
            Path result = temp.resolve("timestamp-option");
            assertEquals(ExitCodes.USAGE, run(arguments(document, option, corpus("timestamps/content.txt"),
                    "--out", result.toString())), option);
            assertTrue(stderr().contains(option), stderr());
            assertFalse(Files.exists(result));
        }
    }

    // Acceptance criterion 4: two runs give identical results.

    @Test
    void resultsAreStableOverTwoRuns() throws Exception {
        Map<String, byte[]> documents = Map.of(
                "signed.p7m", Documents.cades(), "signed.pdf", Documents.pades(), "signed.jws", Documents.jades(),
                "detached.p7s", Documents.cadesDetached(), "signed-t.p7m", Documents.cadesT(),
                "signed.json", Documents.jadesJson());
        Path content = write("content.txt", Documents.CONTENT);
        for (Map.Entry<String, byte[]> entry : documents.entrySet()) {
            Path document = write(entry.getKey(), entry.getValue());
            List<Path> results = new ArrayList<>();
            for (int attempt = 0; attempt < 2; attempt++) {
                Path result = temp.resolve(entry.getKey() + "-" + attempt);
                List<String> args = arguments(document, "--out", result.toString());
                if (entry.getKey().startsWith("detached")) {
                    args.addAll(List.of("--detached", content.toString()));
                }
                assertEquals(ExitCodes.SUCCESS, run(args), stderr());
                DssAlone.Inputs inputs = DssAlone.Inputs.of(entry.getValue(), entry.getKey());
                if (entry.getKey().startsWith("detached")) {
                    inputs = inputs.withDetached(Documents.CONTENT, "content.txt");
                }
                assertValidated(result, inputs, "TOTAL_PASSED", null);
                results.add(result);
            }
            for (String file : List.of("summary.json", "diagnostic-data.xml", "detailed-report.xml",
                    "simple-report.xml")) {
                assertTrue(Arrays.equals(Files.readAllBytes(results.get(0).resolve(file)),
                        Files.readAllBytes(results.get(1).resolve(file))), entry.getKey() + " " + file);
            }
            // The namespace prefixes of this report may differ between runs; its content may not.
            assertEquals(XmlContent.of(results.get(0).resolve("etsi-validation-report.xml")),
                    XmlContent.of(results.get(1).resolve("etsi-validation-report.xml")), entry.getKey());
        }
    }

    @Test
    void theTestDocumentsAreReproducible() throws Exception {
        assertTrue(Arrays.equals(Documents.cades(), Documents.cades()));
        assertTrue(Arrays.equals(Documents.jades(), Documents.jades()));
        assertTrue(Arrays.equals(Documents.jadesJson(), Documents.jadesJson()));
        assertTrue(Arrays.equals(Documents.pades(), Documents.pades()));
        assertTrue(Arrays.equals(Documents.cadesT(), Documents.cadesT()));
        assertTrue(Arrays.equals(Documents.padesTwice(), Documents.padesTwice()));
    }

    /**
     * Writes one test document per format, and the detached content, to
     * {@code target/test-documents}, where continuous integration validates
     * them with the executable JAR, without network.
     */
    @Test
    void theTestDocumentsAreWrittenForTheExecutable() throws Exception {
        Path directory = Files.createDirectories(Path.of("target", "test-documents"));
        Map<String, byte[]> documents = Map.of("signed.p7m", Documents.cades(), "signed.pdf", Documents.pades(),
                "signed.jws", Documents.jades(), "detached.p7s", Documents.cadesDetached(),
                "content.txt", Documents.CONTENT);
        for (Map.Entry<String, byte[]> entry : documents.entrySet()) {
            Files.write(directory.resolve(entry.getKey()), entry.getValue());
            assertTrue(Arrays.equals(entry.getValue(), Files.readAllBytes(directory.resolve(entry.getKey()))));
        }
    }

    @Test
    void aTimestampTokenGivenAsTheDocumentHasNoSignature() throws Exception {
        // DSS validates it as a detached timestamp; validate-timestamp is the mode for tokens.
        Path result = temp.resolve("token");
        assertEquals(ExitCodes.SUCCESS, run(arguments(Path.of(corpus("timestamps/valid.tst")),
                "--out", result.toString())), stderr());
        assertEquals("validated", summary(result).get("result"));
        assertNull(summary(result).get("indication"));
        assertTrue(signatures(result).isEmpty());
        assertAsDssAlone(result, DssAlone.Inputs.of(Files.readAllBytes(CORPUS.resolve("timestamps/valid.tst")),
                "valid.tst"));
    }

    @Test
    void aDocumentWithoutSignaturesIsValidatedWithNone() throws Exception {
        Path result = temp.resolve("unsigned");
        assertEquals(ExitCodes.SUCCESS, run(arguments(write("unsigned.pdf", Documents.pdf()),
                "--out", result.toString())), stderr());
        Map<String, Object> summary = summary(result);
        assertEquals("validated", summary.get("result"), summary.toString());
        assertNull(summary.get("indication"));
        assertNull(summary.get("sub-indication"));
        assertTrue(signatures(result).isEmpty());
        assertAsDssAlone(result, DssAlone.Inputs.of(Documents.pdf(), "unsigned.pdf"));
    }
}
