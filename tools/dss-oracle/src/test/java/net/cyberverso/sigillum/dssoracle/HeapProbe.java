package net.cyberverso.sigillum.dssoracle;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs validate-timestamp once per CRL file given, in one JVM, with the
 * valid corpus token and the CRL in place of crl/ca-ecdsa. It prints one
 * line per run with the exit code, and exits with 1 when a run did not end
 * with exit code 0. The tests start it in a JVM with a small heap.
 */
public final class HeapProbe {

    private HeapProbe() {
    }

    public static void main(String[] crls) throws Exception {
        Path corpus = Path.of("..", "..", "testdata");
        Path out = Files.createTempDirectory("heap-probe");
        int failures = 0;
        for (int i = 0; i < crls.length; i++) {
            List<String> args = new ArrayList<>(List.of("validate-timestamp",
                    "--timestamp", corpus.resolve("timestamps/valid.tst").toString(),
                    "--data", corpus.resolve("timestamps/content.txt").toString(),
                    "--trust-anchor", corpus.resolve("pki/root-ca.pem").toString(),
                    "--certificate", corpus.resolve("pki/ca-ecdsa.pem").toString(),
                    "--crl", crls[i],
                    "--crl", corpus.resolve("crl/root-ca.crl").toString(),
                    "--validation-time", "2030-01-15T10:00:00Z",
                    "--out", out.resolve("run-" + i).toString()));
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int code = Main.run(args.toArray(String[]::new), Modes.RUNNER,
                    new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                    new PrintStream(err, true, StandardCharsets.UTF_8));
            System.out.println(crls[i] + " exit " + code + (code == 0 ? "" : " " + err.toString(StandardCharsets.UTF_8)));
            if (code != 0) {
                failures++;
            }
        }
        System.exit(failures == 0 ? 0 : 1);
    }
}
