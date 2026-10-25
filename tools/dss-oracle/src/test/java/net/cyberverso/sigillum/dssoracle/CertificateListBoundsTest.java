package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CertificateListBoundsTest {

    private static final Path CRL = Path.of("..", "..", "testdata", "crl");

    private static byte[] crl(String name) throws Exception {
        return Files.readAllBytes(CRL.resolve(name + ".crl"));
    }

    private static void assertAccepted(byte[] der) {
        assertEquals(Optional.empty(), CertificateListBounds.check(der));
    }

    private static void assertRejected(byte[] der) {
        assertTrue(CertificateListBounds.check(der).isPresent());
    }

    @Test
    void acceptsEveryCrlOfTheCorpus() throws Exception {
        try (var files = Files.list(CRL)) {
            for (Path file : files.toList()) {
                assertEquals(Optional.empty(), CertificateListBounds.check(Files.readAllBytes(file)), file.toString());
            }
        }
    }

    @Test
    void ignoresTheLengthOfTheOutermostSequenceAndBytesAfterTheCrl() throws Exception {
        byte[] longer = crl("ca-ecdsa");
        longer[3] = (byte) 0xd6;
        assertAccepted(longer);
        byte[] original = crl("ca-ecdsa");
        byte[] indefinite = new byte[original.length - 2];
        indefinite[0] = 0x30;
        indefinite[1] = (byte) 0x80;
        System.arraycopy(original, 4, indefinite, 2, original.length - 4);
        assertAccepted(indefinite);
        byte[] extended = Arrays.copyOf(original, original.length + 7);
        Arrays.fill(extended, original.length, extended.length, (byte) 5);
        assertAccepted(extended);
    }

    @Test
    void acceptsLengthsBeyondTheInputWithinTheSlack() throws Exception {
        // DSS uses a CRL whose last signature octet, a zero, is missing.
        byte[] zero = Crls.caEcdsaSignatureEndingInZero();
        assertAccepted(Arrays.copyOf(zero, zero.length - 1));
        // An element longer than the element that encloses it.
        assertAccepted(new byte[] {0x30, 0x0e, 0x30, 0x03, 0x02, 0x05, 0x01, 0x30, 0x00, 0x03, 0x01, 0x00});
        assertAccepted(Arrays.copyOf(crl("ca-ecdsa"), 300));
        // Cut to 100 bytes, the 229-byte TBSCertList exceeds the 93 remaining bytes plus the 100 of slack.
        assertRejected(Arrays.copyOf(crl("ca-ecdsa"), 100));
    }

    @Test
    void rejectsADefiniteLengthBeyondTheRemainingBytesAndTheSlack() throws Exception {
        byte[] der = crl("root-ca");
        der[103] = (byte) 0x84;
        assertRejected(der);
        // An inner element starts at offset 2 with 4 length octets: 7 octets remain after them.
        byte[] limit = {0x30, (byte) 0x80, 0x30, (byte) 0x84, 0, 0, 0, 0, 0x02, 0x01, 0x00, 0, 0, 0, 0};
        int remaining = limit.length - 8;
        int slack = limit.length;
        limit[7] = (byte) (remaining + slack);
        assertAccepted(limit);
        limit[7] = (byte) (remaining + slack + 1);
        assertRejected(limit);
        assertRejected(Crls.caEcdsaWithLength(4, 64L * 1024 * 1024 - 1));
    }

    @Test
    void acceptsIndefiniteLengthsAsDssDoes() throws Exception {
        assertAccepted(Crls.caEcdsaWithIndefiniteExtensions());
        assertAccepted(Crls.caEcdsaWithIndefiniteEntry());
        byte[] original = crl("ca-ecdsa");
        for (int at : new int[] {5, 237, 249}) {
            byte[] der = original.clone();
            der[at] = (byte) 0x80;
            assertAccepted(der);
        }
    }

    @Test
    void findsAnElementAfterOneThatOverstatesItsLength() {
        // The first inner SEQUENCE says 3 bytes but holds 2; a reader that skips it lands on 0x84.
        byte[] der = {0x30, (byte) 0x80, 0x30, 0x03, 0x02, 0x00, 0x04, (byte) 0x84, 0x7f, 0, 0, 0};
        assertRejected(der);
    }

    @Test
    void allocatesNothingInProportionToDeclaredLengths() throws Exception {
        byte[] der = crl("root-ca");
        der[103] = (byte) 0x84;
        der[104] = 0x7f;
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long before = threads.getCurrentThreadAllocatedBytes();
        assertRejected(der);
        assertTrue(threads.getCurrentThreadAllocatedBytes() - before < 1024 * 1024);
    }
}
