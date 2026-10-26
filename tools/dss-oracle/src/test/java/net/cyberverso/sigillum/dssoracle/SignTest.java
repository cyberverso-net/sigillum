package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests of the sign mode on the inputs of {@code testdata}. Each signature
 * is validated by DSS alone, without any code of the tool, at the validation
 * time of the corpus.
 */
class SignTest {

    private static final String TEXT = Signing.corpus("documents/text.txt");
    private static final String PDF = Signing.corpus("documents/simple.pdf");
    private static final String JSON = Signing.corpus("documents/payload.json");
    /** The issuer of pki/tsa, linked in the timestamp-chain of the B-T entries of the manifest. */
    private static final String TSA_ISSUER = Signing.corpus("pki/ca-ecdsa.pem");

    @TempDir
    Path temp;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(List<String> args) {
        return run(args, Map.of());
    }

    private int run(List<String> args, Map<String, String> environment) {
        out.reset();
        err.reset();
        return Main.run(args.toArray(String[]::new), Modes.runner(environment),
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    private static Stream<Signing.Signer> signers() {
        return Signing.SIGNERS.stream();
    }

    private static List<String> with(List<String> args, String... more) {
        List<String> all = new ArrayList<>(args);
        all.addAll(List.of(more));
        return all;
    }

    private static List<String> with(List<String> args, List<String> more) {
        List<String> all = new ArrayList<>(args);
        all.addAll(more);
        return all;
    }

    private static List<String> without(List<String> args, String option) {
        List<String> all = new ArrayList<>(args);
        int at = all.indexOf(option);
        all.remove(at + 1);
        all.remove(at);
        return all;
    }

    /** The revocation data that a validation of a B-B or B-T signature by {@code signer} needs. */
    private static List<String> revocation(Signing.Signer signer) {
        return List.of(signer.ocsp(), Signing.corpus("ocsp/tsa.der"), Signing.corpus("crl/root-ca.crl"));
    }

    private void assertSigned(int code) {
        assertEquals(ExitCodes.SUCCESS, code, stderr());
    }

    private static void assertPassed(Reports reports, SignatureLevel level) {
        assertPassed(reports, level, Signing.P256);
    }

    /**
     * Checks that DSS validates a signature of {@code signer} at the given
     * level. The default validation policy of DSS 6.5.1 does not authorise
     * EdDSA, so an Ed25519 signature is INDETERMINATE with
     * CRYPTO_CONSTRAINTS_FAILURE_NO_POE there, although its signature
     * value and certificate chain are intact.
     */
    private static void assertPassed(Reports reports, SignatureLevel level, Signing.Signer signer) {
        SimpleReport simple = reports.getSimpleReport();
        String id = simple.getFirstSignatureId();
        String errors = simple.getSubIndication(id) + " " + simple.getAdESValidationErrors(id).stream()
                .map(eu.europa.esig.dss.jaxb.object.Message::getValue).toList();
        if (signer == Signing.ED25519) {
            assertEquals(Indication.INDETERMINATE, simple.getIndication(id), errors);
            assertEquals(eu.europa.esig.dss.enumerations.SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
                    simple.getSubIndication(id), errors);
        } else {
            assertEquals(Indication.TOTAL_PASSED, simple.getIndication(id), errors);
        }
        SignatureWrapper signature = reports.getDiagnosticData().getSignatureById(id);
        assertTrue(signature.isSignatureIntact() && signature.isSignatureValid(), errors);
        assertEquals(level, simple.getSignatureFormat(id));
        assertEquals(Instant.parse(Signing.SIGNING_TIME), simple.getSigningTime(id).toInstant());
    }

    // AC1: the options of the mode.

    private List<String> cadesArguments() {
        return with(Signing.base("cades", "B-B", Signing.P256, TEXT), "--out", temp.resolve("out.p7m").toString());
    }

    @Test
    void eachMandatoryOptionIsRequired() {
        for (String option : List.of("--format", "--level", "--key", "--certificate", "--signing-time",
                "--document", "--out")) {
            assertEquals(ExitCodes.USAGE, run(without(cadesArguments(), option)), option);
            assertTrue(stderr().contains(option), option + ": " + stderr());
        }
    }

    @Test
    void refusesValuesThatAreNotDefined() {
        for (List<String> pair : List.of(List.of("--format", "xades"), List.of("--level", "B-LTA"),
                List.of("--level", "b-b"), List.of("--packaging", "enveloped"),
                List.of("--signature-algorithm", "RSA_MD5"), List.of("--signature-algorithm", "NOT_AN_ALGORITHM"))) {
            List<String> args = new ArrayList<>(cadesArguments());
            int at = args.indexOf(pair.get(0));
            if (at >= 0) {
                args.set(at + 1, pair.get(1));
            } else {
                args.addAll(pair);
            }
            assertEquals(ExitCodes.USAGE, run(args), String.join(" ", pair));
        }
    }

    @Test
    void refusesOptionsThatDoNotApply() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        String pdfOut = temp.resolve("out.pdf").toString();
        List<List<String>> cases = List.of(
                with(Signing.base("pades", "B-B", Signing.P256, PDF), "--packaging", "detached", "--out", pdfOut),
                with(cadesArguments(), "--serialisation", "general"),
                with(Signing.base("jades", "B-B", Signing.P256, JSON), "--out", pdfOut),
                with(with(Signing.base("jades", "B-T", Signing.P256, JSON), "--serialisation", "compact",
                        "--out", pdfOut), Signing.timestamp(tsa)),
                with(cadesArguments(), Signing.timestamp(tsa)),
                with(cadesArguments(), "--crl", Signing.corpus("crl/root-ca.crl")),
                with(cadesArguments(), "--ocsp", Signing.P256.ocsp()),
                with(cadesArguments(), "--trust-anchor", Signing.corpus("pki/root-ca.pem")),
                with(cadesArguments(), "--validation-time", Signing.VALIDATION_TIME),
                with(with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", pdfOut),
                        without(Signing.timestamp(tsa), "--tsa-key")),
                with(with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", pdfOut),
                        without(Signing.timestamp(tsa), "--timestamp-time")),
                with(with(with(Signing.base("cades", "B-LT", Signing.P256, TEXT), "--out", pdfOut),
                        Signing.timestamp(tsa)), without(Signing.longTerm(Signing.P256), "--validation-time")),
                with(with(with(Signing.base("cades", "B-LT", Signing.P256, TEXT), "--out", pdfOut),
                        Signing.timestamp(tsa)), without(Signing.longTerm(Signing.P256), "--trust-anchor")),
                with(cadesArguments(), "--certificate", Signing.RSA.certificate()),
                with(cadesArguments(), "--timestamp-time", Signing.SIGNING_TIME));
        for (List<String> args : cases) {
            assertEquals(ExitCodes.USAGE, run(args), String.join(" ", args));
        }
    }

    @Test
    void refusesFractionsOfASecond() {
        List<String> args = cadesArguments();
        args.set(args.indexOf("--signing-time") + 1, "2029-12-16T10:00:00.5Z");
        assertEquals(ExitCodes.USAGE, run(args));
        assertTrue(stderr().contains("--signing-time"), stderr());
    }

    @Test
    void signOptionsAreRefusedInOtherModes() {
        // --document is also the signed document of validate-document, so it is not listed.
        for (String option : List.of("--format", "--level", "--key", "--chain", "--signing-time",
                "--packaging", "--serialisation", "--signature-algorithm", "--tsa-program", "--tsa-key",
                "--tsa-cert", "--tsa-chain", "--timestamp-time")) {
            assertEquals(ExitCodes.USAGE, run(List.of("validate-certificate", option, "value")), option);
            assertTrue(stderr().contains(option + " is valid only in the mode sign"), stderr());
        }
    }

    @ParameterizedTest
    @MethodSource("signers")
    void signsCadesEnvelopingAtBaselineB(Signing.Signer signer) throws Exception {
        Path signed = temp.resolve("signed.p7m");
        assertSigned(run(with(Signing.base("cades", "B-B", signer, TEXT), "--out", signed.toString())));
        CMSSignedData cms = new CMSSignedData(Files.readAllBytes(signed));
        assertArrayEquals(Files.readAllBytes(Path.of(TEXT)), (byte[]) cms.getSignedContent().getContent());
        assertPassed(Signing.validate(signed, List.of(), revocation(signer), List.of(signer.caCertificate())), SignatureLevel.CAdES_BASELINE_B, signer);
    }

    @ParameterizedTest
    @MethodSource("signers")
    void signsCadesDetachedAtBaselineB(Signing.Signer signer) throws Exception {
        Path signed = temp.resolve("signed.p7s");
        assertSigned(run(with(Signing.base("cades", "B-B", signer, TEXT), "--packaging", "detached",
                "--out", signed.toString())));
        assertTrue(new CMSSignedData(Files.readAllBytes(signed)).isDetachedSignature());
        assertPassed(Signing.validate(signed, List.of(Path.of(TEXT)), revocation(signer),
                List.of(signer.caCertificate())),
                SignatureLevel.CAdES_BASELINE_B, signer);
    }

    @ParameterizedTest
    @MethodSource("signers")
    void signsPadesAtBaselineB(Signing.Signer signer) throws Exception {
        Path signed = temp.resolve("signed.pdf");
        assertSigned(run(with(Signing.base("pades", "B-B", signer, PDF), "--out", signed.toString())));
        byte[] original = Files.readAllBytes(Path.of(PDF));
        byte[] bytes = Files.readAllBytes(signed);
        // An incremental update keeps the original bytes in front (ISO 32000-1:2008, clause 7.5.6).
        assertArrayEquals(original, java.util.Arrays.copyOf(bytes, original.length));
        assertPassed(Signing.validate(signed, List.of(), revocation(signer), List.of(signer.caCertificate())), SignatureLevel.PAdES_BASELINE_B, signer);
    }

    @ParameterizedTest
    @MethodSource("signers")
    void signsJadesInEverySerialisationAtBaselineB(Signing.Signer signer) throws Exception {
        for (String serialisation : List.of("compact", "flattened", "general")) {
            Path signed = temp.resolve(serialisation + ".json");
            assertSigned(run(with(Signing.base("jades", "B-B", signer, JSON), "--serialisation", serialisation,
                    "--out", signed.toString())));
            String text = Files.readString(signed, StandardCharsets.US_ASCII);
            assertEquals(serialisation.equals("compact"), !text.startsWith("{"), serialisation);
            assertEquals(serialisation.equals("general"), text.contains("\"signatures\""), serialisation);
            assertPassed(Signing.validate(signed, List.of(), revocation(signer), List.of(signer.caCertificate())), SignatureLevel.JAdES_BASELINE_B,
                    signer);
        }
    }

    @Test
    void signsJadesDetachedWithObjectIdByUriHash() throws Exception {
        Path signed = temp.resolve("detached.json");
        assertSigned(run(with(Signing.base("jades", "B-B", Signing.P256, JSON), "--serialisation", "flattened",
                "--packaging", "detached", "--out", signed.toString())));
        Map<String, Object> header = protectedHeader(Files.readString(signed, StandardCharsets.US_ASCII));
        String sigD = String.valueOf(header.get("sigD"));
        assertTrue(sigD.contains("http://uri.etsi.org/19182/ObjectIdByURIHash"), sigD);
        assertPassed(Signing.validate(signed, List.of(Path.of(JSON)), revocation(Signing.P256),
                List.of(Signing.P256.caCertificate())),
                SignatureLevel.JAdES_BASELINE_B);
    }

    // AC4: x5c in every JAdES signature.

    @ParameterizedTest
    @MethodSource("signers")
    void jadesCarriesTheCertificateChainInX5c(Signing.Signer signer) throws Exception {
        List<String> expected = new ArrayList<>();
        for (String file : List.of(signer.certificate(), signer.caCertificate(), Signing.corpus("pki/root-ca.pem"))) {
            expected.add(Base64.getEncoder().encodeToString(Pem.decode(Files.readString(Path.of(file)))));
        }
        for (String serialisation : List.of("compact", "flattened", "general")) {
            Path signed = temp.resolve(signer.label() + "-" + serialisation + ".json");
            assertSigned(run(with(Signing.base("jades", "B-B", signer, JSON), "--serialisation", serialisation,
                    "--out", signed.toString())));
            Map<String, Object> header = protectedHeader(Files.readString(signed, StandardCharsets.US_ASCII));
            assertEquals(expected, header.get("x5c"), serialisation);
        }
        // B-T keeps the whole chain. At B-LT, given the root as trust anchor, DSS leaves it out of x5c and
        // holds it among the validation data of etsiU instead.
        Path tsa = Signing.tsaScript(temp, temp.resolve(signer.label() + "-tsa.log"));
        for (String level : List.of("B-T", "B-LT")) {
            for (String serialisation : List.of("flattened", "general")) {
                Path signed = temp.resolve(signer.label() + "-" + level + "-" + serialisation + ".json");
                List<String> args = with(with(Signing.base("jades", level, signer, JSON), "--serialisation",
                        serialisation, "--out", signed.toString()), Signing.timestamp(tsa));
                if (level.equals("B-LT")) {
                    args.addAll(Signing.longTerm(signer));
                }
                assertSigned(run(args));
                Map<String, Object> header = protectedHeader(Files.readString(signed, StandardCharsets.US_ASCII));
                assertEquals(level.equals("B-T") ? expected : expected.subList(0, 2), header.get("x5c"),
                        level + " " + serialisation);
            }
        }
    }

    // AC2: timestamps from sigillum-testpki tsa, at the configured time.

    @Test
    void baselineTTakesItsTimestampFromTheProgramAtTheConfiguredTime() throws Exception {
        Path log = temp.resolve("tsa.log");
        Path tsa = Signing.tsaScript(temp, log);
        Path signed = temp.resolve("signed.p7m");
        List<String> args = with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", signed.toString());
        args.addAll(Signing.timestamp(tsa));
        args.set(args.indexOf("--timestamp-time") + 1, "2029-12-16T10:05:00Z");
        assertSigned(run(args));

        SignerInformation signer = new CMSSignedData(Files.readAllBytes(signed)).getSignerInfos().getSigners()
                .iterator().next();
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(signer.getSignature()));
        // Each option and its value form one argument, so that no value can be read as an option.
        assertEquals(List.of("tsa", "--digest-algorithm=SHA-256", "--digest=" + digest,
                "--time=2029-12-16T10:05:00Z",
                "--tsa-key=" + Signing.corpus("pki/keys/tsa.test-key.pem"),
                "--tsa-cert=" + Signing.corpus("pki/tsa.pem")),
                Files.readAllLines(log, StandardCharsets.UTF_8));

        // Only what the manifest links for a B-T signature: the chain of the signer, and its timestamp-chain,
        // whose pki/ca-ecdsa issues pki/tsa, which the token does not hold.
        Reports reports = Signing.validate(signed, List.of(), revocation(Signing.P256), List.of(TSA_ISSUER));
        assertPassed(reports, SignatureLevel.CAdES_BASELINE_T);
        List<TimestampWrapper> timestamps = reports.getDiagnosticData().getTimestampList();
        assertEquals(1, timestamps.size());
        assertEquals(Instant.parse("2029-12-16T10:05:00Z"), timestamps.get(0).getProductionTime().toInstant());
    }

    @Test
    void anEnvironmentVariableLocatesTheProgram() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        Path signed = temp.resolve("signed.p7m");
        List<String> args = with(with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", signed.toString()),
                without(Signing.timestamp(tsa), "--tsa-program"));
        assertEquals(ExitCodes.USAGE, run(args));
        assertTrue(stderr().contains("SIGILLUM_TESTPKI"), stderr());
        assertSigned(run(args, Map.of(Sign.PROGRAM_VARIABLE, tsa.toString())));
        assertPassed(Signing.validate(signed, List.of(), revocation(Signing.P256), List.of(TSA_ISSUER)),
                SignatureLevel.CAdES_BASELINE_T);
    }

    @Test
    void aFailingProgramFailsTheRun() throws Exception {
        Path signed = temp.resolve("signed.p7m");
        List<String> base = with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", signed.toString());
        Map<String, String> programs = Map.of(
                "exit", "echo 'no key' >&2; exit 1",
                "garbage", "printf 'not a token'",
                "empty", "exit 0",
                "large", "head -c 2000000 /dev/zero");
        for (Map.Entry<String, String> program : programs.entrySet()) {
            Path script = Signing.script(temp.resolve(program.getKey() + ".sh"), program.getValue());
            List<String> args = new ArrayList<>(base);
            args.addAll(Signing.timestamp(script));
            assertEquals(ExitCodes.FAILURE, run(args), program.getKey() + ": " + stderr());
            assertFalse(Files.exists(signed), program.getKey());
        }
        assertTrue(run(with(base, Signing.timestamp(temp.resolve("exit.sh")))) == ExitCodes.FAILURE
                && stderr().contains("no key"), stderr());
        List<String> missing = new ArrayList<>(base);
        missing.addAll(Signing.timestamp(temp.resolve("no-such-program")));
        assertEquals(ExitCodes.FAILURE, run(missing), stderr());
    }

    // AC3: B-LT embeds the revocation data supplied.

    @ParameterizedTest
    @MethodSource("signers")
    void baselineLtEmbedsTheRevocationDataSupplied(Signing.Signer signer) throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        Map<String, List<String>> formats = Map.of(
                "cades", List.of(TEXT, "B-LT"),
                "pades", List.of(PDF, "B-LT"),
                "jades", List.of(JSON, "B-LT"));
        Map<String, SignatureLevel> levels = Map.of("cades", SignatureLevel.CAdES_BASELINE_LT,
                "pades", SignatureLevel.PAdES_BASELINE_LT, "jades", SignatureLevel.JAdES_BASELINE_LT);
        for (Map.Entry<String, List<String>> format : formats.entrySet()) {
            Path signed = temp.resolve("signed-" + format.getKey());
            List<String> args = with(Signing.base(format.getKey(), "B-LT", signer, format.getValue().get(0)),
                    "--out", signed.toString());
            if (format.getKey().equals("jades")) {
                args.addAll(List.of("--serialisation", "general"));
            }
            args.addAll(Signing.timestamp(tsa));
            args.addAll(Signing.longTerm(signer));
            assertSigned(run(args));

            // Without any revocation data supplied, the embedded data suffice.
            Reports reports = Signing.validate(signed, List.of(), List.of(), List.of());
            assertPassed(reports, levels.get(format.getKey()), signer);

            AdvancedSignature signature = SignedDocumentValidator.fromDocument(
                    new InMemoryDocument(Files.readAllBytes(signed))).getSignatures().get(0);
            List<byte[]> responses = new ArrayList<>();
            for (EncapsulatedRevocationTokenIdentifier<?> binary
                    : signature.getCompleteOCSPSource().getAllRevocationBinaries()) {
                responses.add(binary.getBinaries());
            }
            List<byte[]> crls = new ArrayList<>();
            for (EncapsulatedRevocationTokenIdentifier<?> binary
                    : signature.getCompleteCRLSource().getAllRevocationBinaries()) {
                crls.add(binary.getBinaries());
            }
            for (String response : List.of(signer.ocsp(), Signing.corpus("ocsp/tsa.der"))) {
                // A format embeds the OCSPResponse or its BasicOCSPResponse (RFC 6960, section 4.2.1).
                byte[] full = Files.readAllBytes(Path.of(response));
                byte[] basic = ((org.bouncycastle.cert.ocsp.BasicOCSPResp) new OCSPResp(full).getResponseObject())
                        .getEncoded();
                assertTrue(responses.stream().anyMatch(b -> java.util.Arrays.equals(b, basic)
                        || java.util.Arrays.equals(b, full)), format.getKey() + " " + response + " "
                        + responses.size() + " " + crls.size());
            }
            byte[] root = Files.readAllBytes(Path.of(Signing.corpus("crl/root-ca.crl")));
            assertTrue(crls.stream().anyMatch(b -> java.util.Arrays.equals(b, root)), format.getKey());
        }
    }

    // Reproducibility: the corpus is regenerated byte for byte.

    @Test
    void signingTwiceGivesTheSameBytes() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        for (Signing.Signer signer : Signing.SIGNERS) {
            for (List<String> format : List.of(List.of("cades", TEXT), List.of("pades", PDF),
                    List.of("jades", JSON))) {
                byte[] first = null;
                for (int i = 0; i < 2; i++) {
                    Path signed = temp.resolve(signer.label() + "-" + format.get(0) + "-" + i);
                    List<String> args = with(Signing.base(format.get(0), "B-LT", signer, format.get(1)),
                            "--out", signed.toString());
                    if (format.get(0).equals("jades")) {
                        args.addAll(List.of("--serialisation", "general"));
                    }
                    args.addAll(Signing.timestamp(tsa));
                    args.addAll(Signing.longTerm(signer));
                    assertSigned(run(args));
                    byte[] bytes = Files.readAllBytes(signed);
                    if (first == null) {
                        first = bytes;
                    } else {
                        assertArrayEquals(first, bytes, signer.label() + " " + format.get(0));
                    }
                }
            }
        }
    }

    @Test
    void optionsThatDoNotApplyAreReportedInAFixedOrder() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        // Options of B-T at B-B: the first in the order of the usage text is reported.
        assertEquals(ExitCodes.USAGE, run(with(cadesArguments(), "--timestamp-time", Signing.SIGNING_TIME,
                "--tsa-cert", Signing.corpus("pki/tsa.pem"), "--tsa-program", tsa.toString())));
        assertTrue(stderr().contains("--tsa-program applies to B-T and B-LT only."), stderr());
        // Options of B-LT below B-LT.
        assertEquals(ExitCodes.USAGE, run(with(cadesArguments(), "--ocsp", Signing.P256.ocsp(),
                "--crl", Signing.corpus("crl/root-ca.crl"), "--validation-time", Signing.VALIDATION_TIME)));
        assertTrue(stderr().contains("--validation-time applies to B-LT only."), stderr());
    }

    @Test
    void theTsaChainAppliesToBaselineLtOnly() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        List<String> args = with(with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out",
                temp.resolve("out.p7m").toString()), Signing.timestamp(tsa));
        assertEquals(ExitCodes.USAGE, run(with(args, "--tsa-chain", TSA_ISSUER)));
        assertTrue(stderr().contains("--tsa-chain applies to B-LT only."), stderr());
    }

    @Test
    void theValidationTimeIsRequiredAtBaselineLtAndNeverTakenFromTheClock() throws Exception {
        Path tsa = Signing.tsaScript(temp, temp.resolve("tsa.log"));
        List<String> args = with(with(with(Signing.base("cades", "B-LT", Signing.P256, TEXT), "--out",
                temp.resolve("out.p7m").toString()), Signing.timestamp(tsa)),
                without(Signing.longTerm(Signing.P256), "--validation-time"));
        assertEquals(ExitCodes.USAGE, run(args));
        assertTrue(stderr().contains("--validation-time is required at B-LT"), stderr());
        assertFalse(Files.exists(temp.resolve("out.p7m")));
    }

    @Test
    void theTsaProgramMustBeAPath() throws Exception {
        Path signed = temp.resolve("signed.p7m");
        List<String> base = with(Signing.base("cades", "B-T", Signing.P256, TEXT), "--out", signed.toString());
        List<String> bare = with(base, Signing.timestamp(Path.of("sigillum-testpki")));
        assertEquals(ExitCodes.USAGE, run(bare));
        assertTrue(stderr().contains("--tsa-program"), stderr());
        assertTrue(stderr().contains("a path"), stderr());
        List<String> fromEnvironment = with(base, without(Signing.timestamp(Path.of("x")), "--tsa-program"));
        assertEquals(ExitCodes.USAGE, run(fromEnvironment, Map.of(Sign.PROGRAM_VARIABLE, "sigillum-testpki")));
        assertTrue(stderr().contains(Sign.PROGRAM_VARIABLE), stderr());
        assertTrue(stderr().contains("a path"), stderr());
    }

    // Failures.

    @Test
    void aKeyThatDoesNotMatchTheCertificateFails() {
        List<String> args = cadesArguments();
        args.set(args.indexOf("--key") + 1, Signing.corpus("pki/keys/signer-p384.test-key.pem"));
        assertEquals(ExitCodes.FAILURE, run(args));
        assertTrue(stderr().contains("--key"), stderr());
        assertFalse(Files.exists(temp.resolve("out.p7m")));
    }

    @Test
    void anAlgorithmThatDoesNotFitTheKeyIsAUsageError() {
        assertEquals(ExitCodes.USAGE, run(with(cadesArguments(), "--signature-algorithm", "RSA_SHA256")));
        assertTrue(stderr().contains("--signature-algorithm"), stderr());
    }

    @Test
    void anExistingOutputIsKept() throws Exception {
        Path existing = temp.resolve("out.p7m");
        Files.writeString(existing, "keep");
        assertEquals(ExitCodes.FAILURE, run(cadesArguments()));
        assertEquals("keep", Files.readString(existing));
    }

    @Test
    void aMissingInputFails() {
        List<String> args = cadesArguments();
        args.set(args.indexOf("--document") + 1, temp.resolve("missing.txt").toString());
        assertEquals(ExitCodes.FAILURE, run(args));
        assertTrue(stderr().contains("--document"), stderr());
    }

    @Test
    void aSignatureMadeAtBaselineBNeedsNoRevocationDataToBeMade() throws Exception {
        // The signing certificate is not checked against revocation data at B-B and B-T.
        Path signed = temp.resolve("signed.p7m");
        assertSigned(run(with(Signing.base("cades", "B-B", Signing.P256, TEXT), "--out", signed.toString())));
        DiagnosticData data = Signing.validate(signed, List.of(), List.of(), List.of(Signing.P256.caCertificate()))
                .getDiagnosticData();
        SignatureWrapper signature = data.getSignatures().get(0);
        assertTrue(signature.foundRevocations().getRelatedRevocationData().isEmpty());
    }

    /** Decodes the protected header of the first signature of a JWS in any serialisation. */
    private static Map<String, Object> protectedHeader(String jws) {
        String encoded;
        if (jws.startsWith("{")) {
            Matcher matcher = Pattern.compile("\"protected\"\\s*:\\s*\"([A-Za-z0-9_-]+)\"").matcher(jws);
            assertTrue(matcher.find(), jws);
            encoded = matcher.group(1);
        } else {
            encoded = jws.substring(0, jws.indexOf('.'));
        }
        String json = new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
        return JsonReader.object(json);
    }
}
