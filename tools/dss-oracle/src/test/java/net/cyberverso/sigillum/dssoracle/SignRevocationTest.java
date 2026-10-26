package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * At B-LT, the sign mode embeds only revocation data that DSS accepts: a
 * CRL or an OCSP response whose signature does not verify fails the run.
 */
class SignRevocationTest {

    @TempDir
    Path temp;

    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    /**
     * Inverts the last octet of a file, the last octet of its signature
     * value. The response must hold no certificate, as the responses that a
     * CA signs itself, such as ocsp/signer-rsa-2048, hold none (RFC 6960,
     * section 4.2.1); otherwise the last octet belongs to a certificate.
     */
    private Path corrupted(String corpusPath) throws Exception {
        byte[] content = Files.readAllBytes(Signing.CORPUS.resolve(corpusPath));
        content[content.length - 1] ^= (byte) 0xff;
        Path file = temp.resolve("corrupted-" + Path.of(corpusPath).getFileName());
        Files.write(file, content);
        return file;
    }

    private int sign(Signing.Signer signer, String replacedPath, Path replacement) throws Exception {
        Path signed = temp.resolve("signed-" + replacement.getFileName());
        List<String> args = new ArrayList<>(Signing.base("cades", "B-LT", signer,
                Signing.corpus("documents/text.txt")));
        args.addAll(Signing.timestamp(Signing.tsaScript(temp, temp.resolve("tsa.log"))));
        args.addAll(Signing.longTerm(signer));
        args.set(args.indexOf(Signing.corpus(replacedPath)), replacement.toString());
        args.addAll(List.of("--out", signed.toString()));
        err.reset();
        int code = Main.run(args.toArray(String[]::new), Modes.runner(Map.of()),
                new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
        assertFalse(code == ExitCodes.FAILURE ? Files.exists(signed) : false);
        return code;
    }

    @Test
    void anOcspResponseWhoseSignatureDoesNotVerifyFailsTheRun() throws Exception {
        assertEquals(ExitCodes.FAILURE, sign(Signing.RSA, "ocsp/signer-rsa-2048.der",
                corrupted("ocsp/signer-rsa-2048.der")),
                err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void theUncorruptedResponseSigns() throws Exception {
        Path original = temp.resolve("original-signer-rsa-2048.der");
        Files.copy(Signing.CORPUS.resolve("ocsp/signer-rsa-2048.der"), original);
        assertEquals(ExitCodes.SUCCESS, sign(Signing.RSA, "ocsp/signer-rsa-2048.der", original),
                err.toString(StandardCharsets.UTF_8));
    }

    @Test
    void aCrlWhoseSignatureDoesNotVerifyFailsTheRun() throws Exception {
        assertEquals(ExitCodes.FAILURE, sign(Signing.P256, "crl/root-ca.crl", corrupted("crl/root-ca.crl")),
                err.toString(StandardCharsets.UTF_8));
    }
}
