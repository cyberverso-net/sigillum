package net.cyberverso.sigillum.dssoracle;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Checks the lengths that a CRL declares for the elements that DSS 6.5.1
 * reads into memory, without reserving anything in proportion to a declared
 * length. DSS reserves the declared length before it reads the octets, and
 * treats the octets missing at the end of the CRL as zeros: it has been
 * observed to use a CRL that lacks the last, zero, octet of its signature. A
 * length beyond the remaining octets by more than the size of the whole CRL
 * is rejected: no such length can be filled by the file.
 *
 * <p>Which elements DSS reads is described in the README of the tool, under
 * "Declared lengths in CRLs", from its observed behaviour; this class
 * implements that description with the encoding rules of ITU-T X.690
 * (02/2021). In short: the contents of the TBSCertList; the fields of the
 * CRL (RFC 5280, section 5.1) in a flat series of elements that starts in
 * the TBSCertList, except revokedCertificates, which DSS passes over; and the
 * revoked certificate entries with their serial numbers. Elements are
 * recognised by their tag number alone, and the series is read with a
 * cursor that keeps only its position. Where DSS fails on the identifier
 * and length octets, or on an indefinite length that it would read into
 * memory, the check stops without a rejection and leaves the CRL to DSS.
 * Where DSS fails later, when Bouncy Castle cannot decode a field that DSS
 * has read, the check goes on, and may reject the CRL with its own message:
 * DSS rejects it either way.
 */
final class CertificateListBounds {

    private static final int INTEGER = 2;
    private static final int BIT_STRING = 3;
    private static final int SEQUENCE = 16;
    private static final int UTC_TIME = 23;
    private static final int GENERALIZED_TIME = 24;

    /** How DSS treats a field of the CRL that it takes. */
    private enum Use {
        /** It reads the contents into memory. */
        READ,
        /** It passes over the contents by their length. */
        PASSED_OVER
    }

    /**
     * A field of the CRL as DSS recognises it, in the order of RFC 5280,
     * section 5.1. Each is optional.
     */
    private record Field(String name, Predicate<Element> recognised, Use use) {
    }

    private CertificateListBounds() {
    }

    /**
     * Checks a CRL in DER.
     *
     * @param der the CRL
     * @return the problem, or empty when every length that DSS reads into
     *         memory is within the remaining bytes and the slack
     */
    static Optional<String> check(byte[] der) {
        Region crl = new Region(der, 0, der.length);
        Element outer = crl.element(0);
        if (outer == null) {
            return Optional.empty();
        }
        Element tbs = crl.element(outer.contents());
        if (tbs == null) {
            return Optional.empty();
        }
        // The signed data: the contents of the TBSCertList.
        Optional<String> problem = tbs.length() < 0 ? Optional.empty() : crl.tooLong(tbs, "the TBSCertList");
        if (problem.isPresent()) {
            return problem;
        }
        problem = fields(crl, tbs.contents());
        return problem.isPresent() ? problem : entries(crl, tbs.contents());
    }

    /** The fields of the CRL, as DSS recognises them in the series. */
    private static List<Field> fieldsOfACrl(Region crl) {
        return List.of(
                new Field("version", e -> e.tagNumber() == INTEGER, Use.READ),
                new Field("signature", e -> e.tagNumber() == SEQUENCE, Use.READ),
                new Field("issuer", e -> e.tagNumber() == SEQUENCE, Use.READ),
                new Field("thisUpdate", CertificateListBounds::time, Use.READ),
                new Field("nextUpdate", CertificateListBounds::time, Use.READ),
                new Field("revokedCertificates", e -> e.tagNumber() == SEQUENCE
                        && (e.length() <= 0 || crl.firstTagNumberIs(e, SEQUENCE)), Use.PASSED_OVER),
                // A tag of the context-specific or private class (X.690, clause 8.1.2.2): [0] in RFC 5280.
                new Field("crlExtensions", e -> (e.identifier() & 0x80) != 0, Use.READ),
                new Field("signatureAlgorithm", e -> e.tagNumber() == SEQUENCE, Use.READ),
                new Field("signatureValue", e -> e.tagNumber() == BIT_STRING, Use.READ));
    }

    /** Checks the fields that DSS reads into memory. */
    private static Optional<String> fields(Region crl, int start) {
        Cursor series = new Cursor(crl, start);
        Element element = series.next();
        for (Field field : fieldsOfACrl(crl)) {
            if (element == null) {
                // DSS cannot read the next identifier and length octets, and fails.
                return Optional.empty();
            }
            if (field.use() == Use.PASSED_OVER && element.tagNumber() == SEQUENCE && element.length() > 0
                    && !crl.firstReadable(element)) {
                // DSS looks at the first element of a non-empty SEQUENCE here, and fails if it cannot read it.
                return Optional.empty();
            }
            if (!field.recognised().test(element)) {
                continue;
            }
            if (field.use() == Use.READ) {
                if (element.length() < 0) {
                    // DSS fails on an element of indefinite length that it reads into memory.
                    return Optional.empty();
                }
                Optional<String> problem = crl.tooLong(element, "the " + field.name());
                if (problem.isPresent()) {
                    return problem;
                }
            }
            // A revokedCertificates of indefinite length is passed over by no octet: the next field is taken from
            // its contents, as DSS takes it.
            element = series.next();
        }
        return Optional.empty();
    }

    /** Checks the revoked certificate entries and their serial numbers, which DSS reads into memory. */
    private static Optional<String> entries(Region crl, int start) {
        Cursor series = new Cursor(crl, start);
        Element element = series.next();
        while (element != null && !time(element)) {
            element = series.next();
        }
        if (element == null) {
            return Optional.empty();
        }
        element = series.next();
        if (element != null && time(element)) {
            element = series.next();
        }
        if (element == null || element.tagNumber() != SEQUENCE) {
            return Optional.empty();
        }
        int position = element.contents();
        while (position < crl.end()) {
            Element entry = crl.element(position);
            if (entry == null || entry.tagNumber() != SEQUENCE || entry.length() < 0) {
                // The end of the entries; on an indefinite length DSS fails, and decides on the CRL.
                return Optional.empty();
            }
            Optional<String> problem = crl.tooLong(entry, "a revoked certificate entry");
            if (problem.isPresent()) {
                return problem;
            }
            // The length is within the slack, so the end is below three times the largest input of the tool.
            Region contents = new Region(crl.der(), entry.contents(), (int) (entry.contents() + entry.length()));
            Element serial = contents.element(entry.contents());
            if (serial == null) {
                return Optional.empty();
            }
            if (serial.tagNumber() == INTEGER) {
                if (serial.length() < 0) {
                    return Optional.empty();
                }
                problem = contents.tooLong(serial, "the serial number of a revoked certificate entry");
                if (problem.isPresent()) {
                    return problem;
                }
                if (!contents.validInteger(serial)) {
                    return Optional.empty();
                }
            }
            position = entry.next(crl.end());
        }
        return Optional.empty();
    }

    private static boolean time(Element element) {
        return element.tagNumber() == UTC_TIME || element.tagNumber() == GENERALIZED_TIME;
    }

    /**
     * The identifier and length octets of an element.
     *
     * @param offset the offset of the identifier octets
     * @param identifier the leading identifier octet
     * @param tagNumber the tag number (X.690, clause 8.1.2)
     * @param length the length, -1 for the indefinite form
     * @param contents the offset of the first contents octet
     */
    private record Element(int offset, int identifier, int tagNumber, long length, int contents) {

        /** The offset after the contents, as far as the end. */
        int next(int end) {
            return (int) Math.min(end, contents + Math.max(0, length));
        }
    }

    /**
     * The series of elements from a position to the end of a region, each
     * starting where the previous one ends by its declared length, up to the
     * first whose identifier and length octets cannot be read. It keeps only
     * its position, so a series of any length takes constant memory.
     */
    private static final class Cursor {
        private final Region region;
        private int position;
        private boolean ended;

        Cursor(Region region, int position) {
            this.region = region;
            this.position = position;
        }

        /** The next element, or {@code null} at the end of the series. */
        Element next() {
            if (ended || position >= region.end()) {
                ended = true;
                return null;
            }
            Element element = region.element(position);
            if (element == null) {
                ended = true;
                return null;
            }
            position = element.next(region.end());
            return element;
        }
    }

    /**
     * Octets from a start to an end, which may lie past the end of the CRL:
     * there, DSS reads zeros, as in an entry that declares more octets than
     * the CRL holds.
     */
    private record Region(byte[] der, int start, int end) {

        private int octet(int at) {
            return at < der.length ? der[at] & 0xff : 0;
        }

        /**
         * Reads the identifier and length octets at a position, or returns
         * {@code null} when DSS cannot read them: the end comes first, the
         * first subsequent octet of a high tag number has bits 7 to 1 zero
         * (X.690, clause 8.1.2.4.2 c)), the initial length octet is 0xFF
         * (clause 8.1.3.5 c)), or the length is above 2^31 - 1.
         */
        Element element(int position) {
            long tag = identifierAt(position);
            if (tag < 0) {
                return null;
            }
            int tagNumber = (int) tag;
            int at = (int) (tag >>> 32);
            if (at >= end) {
                return null;
            }
            int initial = octet(at++);
            long length;
            if (initial == 0x80) {
                length = -1;
            } else if (initial == 0xff) {
                return null;
            } else if (initial < 0x80) {
                length = initial;
            } else {
                length = 0;
                for (int count = initial & 0x7f; count > 0; count--) {
                    if (at >= end) {
                        return null;
                    }
                    length = length * 256 + octet(at++);
                    if (length > Integer.MAX_VALUE) {
                        return null;
                    }
                }
            }
            return new Element(position, octet(position), tagNumber, length, at);
        }

        /**
         * Reads the identifier octets at a position (X.690, clause 8.1.2):
         * the tag number in the low 32 bits and the offset after them in the
         * high ones, or -1 when they cannot be read. A high tag number is in
         * base 128, with bit 8 set on every subsequent octet but the last
         * (clause 8.1.2.4.2), and kept modulo 2^32, as a 32-bit integer
         * keeps it: refusing larger ones would stop the check where DSS may
         * read on.
         */
        private long identifierAt(int position) {
            int at = position;
            if (at >= end) {
                return -1;
            }
            int tagNumber = octet(at++) & 0x1f;
            if (tagNumber == 0x1f) {
                tagNumber = 0;
                boolean first = true;
                while (true) {
                    if (at >= end) {
                        return -1;
                    }
                    int subsequent = octet(at++);
                    if (first && (subsequent & 0x7f) == 0) {
                        // Clause 8.1.2.4.2 c).
                        return -1;
                    }
                    first = false;
                    tagNumber = tagNumber * 128 + (subsequent & 0x7f);
                    if ((subsequent & 0x80) == 0) {
                        break;
                    }
                }
            }
            return ((long) at << 32) | (tagNumber & 0xffffffffL);
        }

        /** Whether the identifier octets of the first element in the contents can be read. */
        boolean firstReadable(Element element) {
            return identifierAt(element.contents()) >= 0;
        }

        /** Whether the first element in the contents has a tag number. */
        boolean firstTagNumberIs(Element element, int tagNumber) {
            long tag = identifierAt(element.contents());
            return tag >= 0 && (int) tag == tagNumber;
        }

        /** The rejection of an element whose length exceeds the remaining octets and the slack, if it does. */
        Optional<String> tooLong(Element element, String what) {
            long remaining = Math.max(0, end - element.contents());
            // The slack, the size of the CRL, keeps the short reads that DSS accepts.
            long limit = remaining + der.length;
            if (element.length() <= limit) {
                return Optional.empty();
            }
            return Optional.of(what + " at offset " + element.offset() + " declares " + element.length()
                    + " bytes, more than the " + remaining + " bytes that remain plus the size of the CRL, "
                    + der.length + "; DSS reads it into memory at that length");
        }

        /**
         * Whether the contents of an INTEGER, zeros past the end of the
         * region, are a valid encoding (X.690, clauses 8.3.1 and 8.3.2): at
         * least one octet, and, with more than one, the first octet and bit
         * 8 of the second not all zeros or all ones. Only those two octets
         * are read.
         */
        boolean validInteger(Element integer) {
            if (integer.length() == 0) {
                return false;
            }
            if (integer.length() == 1) {
                return true;
            }
            int first = contentOctet(integer.contents());
            int second = contentOctet(integer.contents() + 1);
            boolean redundant = first == 0 && (second & 0x80) == 0 || first == 0xff && (second & 0x80) != 0;
            return !redundant;
        }

        private int contentOctet(int at) {
            return at < end ? octet(at) : 0;
        }
    }
}
