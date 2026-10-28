package net.cyberverso.sigillum.dssoracle;

import java.util.Optional;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Checks the lengths that a CRL declares where the CRL parser of DSS 6.5.1
 * ({@code dss-crl-parser-stream}) reads an element into an array of that
 * length, without allocating anything in proportion to a declared length.
 * DSS allocates the declared length before it reads the octets, and treats
 * the octets missing at the end of the CRL as zeros: it has been observed to
 * use a CRL that lacks the last, zero, octet of its signature. A length
 * beyond the remaining octets by more than the size of the whole CRL is
 * rejected: no such length can be filled by the file, and DSS has been
 * observed to use memory in proportion to it, several times over.
 *
 * <p>The parser reads a CRL (RFC 5280, section 5.1) as a stream, in three
 * passes, and the walk follows each of them:
 *
 * <ul>
 * <li>the information of the CRL: it enters the CertificateList and the
 * TBSCertList, whatever their identifier octets, then reads into arrays the
 * version, signature, issuer, thisUpdate and nextUpdate that it finds in
 * that order, by tag number; skips revokedCertificates without reading it
 * into an array; and reads into arrays the crlExtensions, then the
 * signatureAlgorithm and the signatureValue of the CertificateList. It reads
 * nothing after the signatureValue;</li>
 * <li>the signed data: the contents of the TBSCertList, by its declared
 * length;</li>
 * <li>the entry of a serial number: it skips the elements of the
 * TBSCertList up to thisUpdate, and nextUpdate, then reads each SEQUENCE
 * that follows into an array, and the serial number INTEGER at its start
 * into another. It stops at the first element that is not a SEQUENCE, at the
 * end of the CRL, and at an entry from which Bouncy Castle cannot rebuild the
 * serial number. It also stops at the entry of the serial number asked for;
 * since any certificate of a run may ask, the walk reads on as if none
 * matched.</li>
 * </ul>
 *
 * <p>The identifier octets are read as ITU-T X.690 (02/2021), clause 8.1.2,
 * specifies, including the high tag number form of clause 8.1.2.4, and the
 * length octets as clause 8.1.3 specifies: the short form (8.1.3.4), the long
 * form (8.1.3.5) and the indefinite form (8.1.3.6). The tag number is
 * compared as DSS compares it, without the class and the constructed bit.
 * Where DSS fails or stops reading, on incomplete or reserved octets, a
 * length of more than 31 bits or an indefinite length that it would read
 * into an array, the walk stops that pass without a rejection: DSS decides
 * on them. Elements that DSS does not read, such as bytes after the
 * signatureValue, or the contents of an element read into an array, which
 * Bouncy Castle then parses within that array, are not checked.
 */
final class CertificateListBounds {

    private static final int INTEGER = 2;
    private static final int BIT_STRING = 3;
    private static final int SEQUENCE = 16;
    private static final int UTC_TIME = 23;
    private static final int GENERALIZED_TIME = 24;

    private CertificateListBounds() {
    }

    /**
     * Checks a CRL in DER.
     *
     * @param der the CRL
     * @return the problem, or empty when every length that DSS reads into an
     *         array is within the remaining bytes and the slack
     */
    static Optional<String> check(byte[] der) {
        try {
            information(der);
            signedData(der);
            entries(der);
            return Optional.empty();
        } catch (TooLong e) {
            return Optional.of(e.getMessage());
        }
    }

    /** The pass of the information of the CRL. */
    private static void information(byte[] der) throws TooLong {
        Reader in = new Reader(der, 0, der.length);
        try {
            in.header();
            in.header();
            Header h = in.header();
            if (h.tagNumber() == INTEGER) {
                h = in.readNext(h);
            }
            if (h.tagNumber() == SEQUENCE) {
                h = in.readNext(h);
            }
            if (h.tagNumber() == SEQUENCE) {
                h = in.readNext(h);
            }
            if (date(h)) {
                h = in.readNext(h);
            }
            if (date(h)) {
                h = in.readNext(h);
            }
            if (h.tagNumber() == SEQUENCE) {
                if (h.length() > 0) {
                    // DSS looks at the tag number of the first element without consuming it.
                    int mark = in.position;
                    int first = in.tagNumber(in.identifier());
                    in.position = mark;
                    if (first == SEQUENCE) {
                        in.skip(h.length());
                        h = in.header();
                    }
                } else {
                    h = in.header();
                }
            }
            if ((h.identifier() & 0x80) != 0) {
                h = in.readNext(h);
            }
            if (h.tagNumber() == SEQUENCE) {
                h = in.readNext(h);
            }
            if (h.tagNumber() == BIT_STRING) {
                in.read(h);
            }
        } catch (Stop e) {
            // DSS fails or stops here; it decides on the CRL.
        }
    }

    /** The pass of the signed data, the contents of the TBSCertList. */
    private static void signedData(byte[] der) throws TooLong {
        Reader in = new Reader(der, 0, der.length);
        try {
            in.header();
            in.read(in.header());
        } catch (Stop e) {
            // DSS fails here; it decides on the CRL.
        }
    }

    /** The pass of the entry of a serial number, read as if no entry matched. */
    private static void entries(byte[] der) throws TooLong {
        Reader in = new Reader(der, 0, der.length);
        try {
            in.header();
            in.header();
            Header h;
            do {
                h = in.header();
                in.skip(h.length());
            } while (!date(h));
            h = in.header();
            if (date(h)) {
                in.skip(h.length());
                h = in.header();
            }
            while (h.tagNumber() == SEQUENCE) {
                if (in.atEnd()) {
                    return;
                }
                h = in.header();
                if (h.tagNumber() != SEQUENCE) {
                    in.skip(h.length());
                    continue;
                }
                int start = in.position;
                in.read(h);
                if (!serialNumberReadable(der, start, h.length())) {
                    return;
                }
            }
        } catch (Stop e) {
            // DSS stops reading entries here.
        }
    }

    /**
     * Reads the serial number at the start of an entry, as DSS reads it from
     * the array of the entry, zeros after the end of the CRL included.
     *
     * @return whether DSS goes on to the next entry
     */
    private static boolean serialNumberReadable(byte[] der, int start, long length) throws TooLong, Stop {
        Reader entry = new Reader(der, start, (int) length);
        Header serial = entry.header();
        if (serial.tagNumber() != INTEGER) {
            return true;
        }
        int contents = entry.position;
        entry.read(serial);
        byte[] value = new byte[(int) serial.length()];
        for (int i = 0; i < value.length; i++) {
            // Past the end of the entry, the array of DSS holds zeros.
            value[i] = contents + i < entry.end ? entry.octetAt(contents + i) : 0;
        }
        byte[] lengthOctets = definiteLength(value.length);
        byte[] encoding = new byte[1 + lengthOctets.length + value.length];
        encoding[0] = INTEGER;
        System.arraycopy(lengthOctets, 0, encoding, 1, lengthOctets.length);
        System.arraycopy(value, 0, encoding, 1 + lengthOctets.length, value.length);
        try {
            // DSS rebuilds the INTEGER so, and stops reading the entries when Bouncy Castle refuses it.
            ASN1Primitive.fromByteArray(encoding);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** The length octets of a definite length in the shortest form (X.690, clause 10.1). */
    private static byte[] definiteLength(int length) {
        if (length < 0x80) {
            return new byte[] {(byte) length};
        }
        int size = 4 - Integer.numberOfLeadingZeros(length) / 8;
        byte[] octets = new byte[1 + size];
        octets[0] = (byte) (0x80 | size);
        for (int i = 0; i < size; i++) {
            octets[1 + i] = (byte) (length >>> (8 * (size - 1 - i)));
        }
        return octets;
    }

    private static boolean date(Header h) {
        return h.tagNumber() == UTC_TIME || h.tagNumber() == GENERALIZED_TIME;
    }

    /**
     * The identifier and length octets of an element.
     *
     * @param identifier the leading identifier octet
     * @param tagNumber the tag number, as DSS computes it
     * @param length the length, -1 for the indefinite form
     */
    private record Header(int identifier, int tagNumber, long length) {
    }

    /** DSS fails or stops reading at this point. */
    private static final class Stop extends Exception {
        private static final long serialVersionUID = 1L;

        Stop() {
            super(null, null, false, false);
        }
    }

    /** A length beyond the remaining octets and the slack, where DSS reads it into an array. */
    private static final class TooLong extends Exception {
        private static final long serialVersionUID = 1L;

        TooLong(String message) {
            super(message, null, false, false);
        }
    }

    /**
     * Reads a stream of octets as DSS reads it: the CRL, or the array of an
     * entry, which holds zeros past the end of the CRL.
     */
    private static final class Reader {
        private final byte[] der;
        private final int start;
        private final int end;
        private int position;

        Reader(byte[] der, int start, int length) {
            this.der = der;
            this.start = start;
            this.end = start + length;
            this.position = start;
        }

        boolean atEnd() {
            return position >= end;
        }

        byte octetAt(int at) {
            return at < der.length ? der[at] : 0;
        }

        /** Reads one octet, or -1 at the end. */
        int next() {
            return position < end ? octetAt(position++) & 0xff : -1;
        }

        int identifier() throws Stop {
            int identifier = next();
            if (identifier < 0) {
                // DSS reads the end as a high tag number form and fails on it.
                throw new Stop();
            }
            return identifier;
        }

        /** The tag number (clause 8.1.2.4.2), whose value DSS keeps in 32 bits. */
        int tagNumber(int identifier) throws Stop {
            int number = identifier & 0x1f;
            if (number != 0x1f) {
                return number;
            }
            int b = next();
            if ((b & 0x7f) == 0 && b >= 0) {
                throw new Stop();
            }
            number = 0;
            while (b >= 0 && (b & 0x80) != 0) {
                number = (number | (b & 0x7f)) << 7;
                b = next();
            }
            if (b < 0) {
                throw new Stop();
            }
            return number | (b & 0x7f);
        }

        /** The length octets (clause 8.1.3), as DSS reads them. */
        long length() throws Stop {
            int initial = next();
            if (initial < 0 || initial == 0xff) {
                throw new Stop();
            }
            if (initial < 0x80) {
                return initial;
            }
            if (initial == 0x80) {
                return -1;
            }
            int count = initial & 0x7f;
            int length = 0;
            for (int i = 0; i < count; i++) {
                int octet = next();
                if (octet < 0 || (length >>> 23) != 0) {
                    // DSS refuses a length of more than 31 bits.
                    throw new Stop();
                }
                length = (length << 8) + octet;
            }
            return length;
        }

        Header header() throws Stop {
            int identifier = identifier();
            int number = tagNumber(identifier);
            return new Header(identifier, number, length());
        }

        /** Skips the contents of an element, as DSS skips them, up to the end. */
        void skip(long length) {
            if (length > 0) {
                position = (int) Math.min(end, position + length);
            }
        }

        /** Reads the contents of an element into an array, as DSS does, after checking its length. */
        void read(Header h) throws TooLong, Stop {
            if (h.length() < 0) {
                // DSS fails on an array of negative size.
                throw new Stop();
            }
            long remaining = Math.max(0, end - position);
            // The slack, the size of the CRL, keeps the short reads that DSS accepts.
            long limit = remaining + der.length;
            if (h.length() > limit) {
                throw new TooLong("an element at offset " + (position - start) + (start == 0 ? "" : " of the entry"
                        + " at offset " + start) + " declares " + h.length() + " bytes, more than the " + remaining
                        + " bytes that remain plus the size of the CRL, " + der.length
                        + ", and the CRL parser of DSS reads it into an array of that size");
            }
            position = (int) Math.min(end, position + h.length());
        }

        /** Reads the contents of an element into an array, then the next header. */
        Header readNext(Header h) throws TooLong, Stop {
            read(h);
            return header();
        }
    }
}
