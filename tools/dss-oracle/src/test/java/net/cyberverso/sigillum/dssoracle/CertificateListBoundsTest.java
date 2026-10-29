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
    void findsAnElementWhereTheParserOfDssLandsAfterOneThatOverstatesItsLength() {
        // The version INTEGER says 3 octets but holds 1; DSS reads the next two as part of it and lands on 0x30 0x84.
        byte[] der = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x02, 0x03, 0x01, 0x30, 0x00, 0x30, (byte) 0x84, 0x7f,
            0, 0, 0};
        assertRejected(der);
    }

    /**
     * Issue #72, case 1: the TBSCertList tag 0x30 becomes 0x10, without the
     * constructed bit. The parser of DSS reads the identifier and length
     * octets of the TBSCertList whatever its tag, and then the nextUpdate,
     * whose length octet becomes 0x84: a length of about 858 MB.
     */
    @Test
    void readsTheTbsCertListWhateverItsTagAsDssDoes() throws Exception {
        byte[] der = crl("root-ca");
        der[4] = 0x10;
        der[103] = (byte) 0x84;
        assertRejected(der);
    }

    /** Issue #72, case 2: DSS stops reading after the signature value, so bytes after it are never read. */
    @Test
    void ignoresElementsAfterTheSignatureValueAsDssDoes() throws Exception {
        byte[] original = crl("ca-ecdsa");
        for (byte[] trailing : new byte[][] {
            {0x04, (byte) 0x84, 0x03, (byte) 0xff, (byte) 0xff, (byte) 0xff},
            {0x04, (byte) 0x84, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff}}) {
            byte[] der = Arrays.copyOf(original, original.length + trailing.length);
            System.arraycopy(trailing, 0, der, original.length, trailing.length);
            assertAccepted(der);
        }
    }

    /**
     * Issue #72, case 3: the identifier octet of the signatureValue BIT
     * STRING of crl/root-ca, at offset 181, gets the constructed bit. DSS
     * reads the contents as the signature value, not as encodings.
     */
    @Test
    void readsTheSignatureValueAsOctetsWhateverItsTagAsDssDoes() throws Exception {
        for (int tag : new int[] {0x23, 0x63, 0xa3, 0xe3}) {
            byte[] der = crl("root-ca");
            der[181] = (byte) tag;
            assertAccepted(der);
        }
    }

    @Test
    void leavesALengthThatDssSkipsWithoutReadingIt() {
        // revokedCertificates declares 0x7f000000 octets; DSS skips it without allocating, then fails at the end.
        byte[] der = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, (byte) 0x84, 0x7f, 0, 0, 0, 0x30, 0x00};
        assertAccepted(der);
    }

    @Test
    void checksTheRevokedCertificateEntriesAndTheirSerialNumbersAsDssReadsThem() {
        // An entry of revokedCertificates declares 0x7f000000 octets, which DSS reads into an array.
        byte[] entry = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, 0x08, 0x30, (byte) 0x84, 0x7f, 0, 0, 0, 0x02, 0x00};
        assertRejected(entry);
        // The serial number of an entry declares 0x7f000000 octets.
        byte[] serial = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, 0x08, 0x30, 0x06, 0x02, (byte) (0x84), 0x7f, 0, 0, 0};
        assertRejected(serial);
        // DSS stops reading the entries at a serial number that Bouncy Castle refuses, here an empty INTEGER.
        byte[] afterMalformed = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, 0x0a, 0x30, 0x02, 0x02, 0x00, 0x30, (byte) 0x84, 0x7f, 0, 0, 0};
        assertAccepted(afterMalformed);
        // An empty entry stops it too: DSS cannot read an identifier octet in it.
        byte[] afterEmpty = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, 0x08, 0x30, 0x00, 0x30, (byte) 0x84, 0x7f, 0, 0, 0};
        assertAccepted(afterEmpty);
    }

    /**
     * Thousands of short revoked certificate entries, each with a serial
     * number INTEGER that declares as many octets as the whole CRL and
     * starts with a valid octet: every length is within the slack, and the
     * check must take memory in proportion to the CRL, not to the declared
     * lengths times the entries (issue #72).
     */
    @Test
    void manyEntriesDeclaringLongSerialNumbersTakeMemoryInProportionToTheCrl() {
        int entries = 8000;
        int entrySize = 9;
        byte[] head = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00};
        int revokedHeader = 6;
        int size = head.length + revokedHeader + entries * entrySize;
        byte[] der = new byte[size];
        System.arraycopy(head, 0, der, 0, head.length);
        int at = head.length;
        der[at++] = 0x30;
        der[at++] = (byte) 0x84;
        int revokedLength = entries * entrySize;
        for (int shift = 24; shift >= 0; shift -= 8) {
            der[at++] = (byte) (revokedLength >>> shift);
        }
        for (int i = 0; i < entries; i++) {
            der[at++] = 0x30;
            der[at++] = 0x07;
            der[at++] = 0x02;
            der[at++] = (byte) 0x84;
            for (int shift = 24; shift >= 0; shift -= 8) {
                der[at++] = (byte) (size >>> shift);
            }
            der[at++] = 0x01;
        }
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        long before = threads.getCurrentThreadAllocatedBytes();
        assertAccepted(der);
        long allocated = threads.getCurrentThreadAllocatedBytes() - before;
        assertTrue(allocated < 16L * 1024 * 1024, "allocated " + allocated + " bytes for a CRL of " + size);
    }

    /**
     * With revokedCertificates of indefinite length, DSS does not reach the
     * signatureAlgorithm and signatureValue of the CRL; the check of the
     * fields stops there, and the entries are still checked (issue #72).
     */
    @Test
    void stopsTheFieldsAtARevokedCertificatesOfIndefiniteLength() {
        byte[] signatureAfter = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, (byte) 0x80, 0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x30, 0x00, 0x03, (byte) 0x84, 0x40, 0, 0, 0};
        assertAccepted(signatureAfter);
        byte[] longEntry = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, (byte) 0x80, 0x30, (byte) 0x84, 0x40, 0, 0, 0, 0x02, 0x01, 0x01, 0x00, 0x00};
        assertRejected(longEntry);
    }

    /**
     * DSS takes for crlExtensions an element of the context-specific or
     * private class only; one of the application class with tag number 16
     * is taken for the signatureAlgorithm, and its length is checked.
     */
    @Test
    void takesAnApplicationClassElementForTheNextFieldOfItsTagNumber() {
        byte[] application = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x70, (byte) 0x84, 0x40, 0, 0, 0, 0x02, 0x01, 0x00};
        assertRejected(application);
    }

    /** A serial number that overruns its entry is read with zeros past the end of the entry. */
    @Test
    void readsZerosPastTheEndOfAnEntry() {
        // The serial number declares two octets and holds 0x00: with a zero after it, it has a redundant
        // leading octet, DSS stops reading the entries, and the long entry after it is not checked.
        byte[] redundant = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x30, 0x00, 0x30, 0x00, 0x17, 0x00,
            0x30, 0x0b, 0x30, 0x03, 0x02, 0x02, 0x00, 0x30, (byte) 0x84, 0x40, 0, 0, 0};
        assertAccepted(redundant);
        // Holding 0x05, it is valid with the zero, and DSS reads the next entry.
        byte[] valid = redundant.clone();
        valid[16] = 0x05;
        assertRejected(valid);
    }

    /**
     * Tag numbers are kept in 32 bits: a high tag number of 2^32 + 16 is
     * taken for 16, a SEQUENCE, and its length is checked; one of 2^31 + 16
     * is negative and matches no field.
     */
    @Test
    void keepsTagNumbersInThirtyTwoBits() {
        byte[] wrapped = {0x30, (byte) 0x80, 0x30, (byte) 0x80, 0x1f, (byte) 0x90, (byte) 0x80, (byte) 0x80,
            (byte) 0x80, 0x10, (byte) 0x84, 0x40, 0, 0, 0};
        assertRejected(wrapped);
        byte[] negative = wrapped.clone();
        negative[5] = (byte) 0x88;
        assertAccepted(negative);
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
