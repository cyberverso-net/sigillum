package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Validates the valid corpus token with DSS alone, without any code of the
 * tool, with the CRL given in place of crl/ca-ecdsa, and prints the
 * indication or the failure. The tests start it in a JVM with a small heap.
 */
public final class CrlAloneProbe {

    private CrlAloneProbe() {
    }

    public static void main(String[] args) throws Exception {
        Path corpus = Path.of("..", "..", "testdata");
        MutationTest.Setup corpusSetup = MutationTest.Setup.corpus(
                Files.readAllBytes(corpus.resolve("timestamps/valid.tst")));
        MutationTest.Setup setup = new MutationTest.Setup(corpusSetup.token(), corpusSetup.anchors(),
                corpusSetup.certificates(), List.of(Files.readAllBytes(Path.of(args[0])),
                        Files.readAllBytes(corpus.resolve("crl/root-ca.crl"))), corpusSetup.responses());
        MutationTest.RawResult result = MutationTest.rawDss(setup);
        System.out.println(result.failure() != null ? "failure " + result.failure() : "indication "
                + result.indication());
    }
}
