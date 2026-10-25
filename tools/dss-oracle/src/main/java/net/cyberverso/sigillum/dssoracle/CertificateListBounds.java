package net.cyberverso.sigillum.dssoracle;

import java.util.ArrayDeque;
import java.util.BitSet;
import java.util.Deque;
import java.util.Optional;

/**
 * Checks the lengths that a CRL declares against the size of the CRL,
 * without allocating anything in proportion to a declared length. A length
 * may run past the bytes that hold it: DSS 6.5.1 has been observed to use a
 * CRL that lacks the last, zero, octet of its signature. A length beyond the
 * remaining bytes by more than the size of the whole CRL is rejected: DSS
 * has been observed to use memory in proportion to a declared length, several
 * times over, and no such length can be filled by the file.
 *
 * <p>The identifier octets are read as ITU-T X.690 (02/2021), clause 8.1.2,
 * specifies, including the high tag number form of clause 8.1.2.4, and the
 * length octets as clause 8.1.3 specifies: the short form (8.1.3.4), the long
 * form (8.1.3.5) and the indefinite form (8.1.3.6). Starting from the first
 * octet, the walk visits every position where a reader that goes through the
 * encoding in order can meet identifier octets: the contents of a
 * constructed element (clause 8.1.2.5) or of an element of indefinite length,
 * and the position after the contents of an element of definite length. It
 * keeps one bit per input octet to visit each position once, so it uses
 * memory and time in proportion to the input.
 *
 * <p>Only definite lengths are judged. The indefinite form is left to DSS,
 * which has been observed to use a CRL with an indefinite length in its
 * extensions. The length of the outermost SEQUENCE is not checked: DSS has
 * been observed to use a CRL whose outer length is wrong. Incomplete
 * identifier or length octets, and the reserved initial length octet of
 * clause 8.1.3.5 c), end the walk at that position without a rejection; DSS
 * decides on them.
 */
final class CertificateListBounds {

    private CertificateListBounds() {
    }

    /**
     * Checks a CRL in DER.
     *
     * @param der the CRL
     * @return the problem, or empty when every length is within the remaining
     *         bytes and the slack
     */
    static Optional<String> check(byte[] der) {
        BitSet visited = new BitSet(der.length);
        Deque<Integer> pending = new ArrayDeque<>();
        pending.push(0);
        while (!pending.isEmpty()) {
            int position = pending.pop();
            if (position >= der.length || visited.get(position)) {
                continue;
            }
            visited.set(position);
            Header header = Header.read(der, position);
            if (header == null) {
                continue;
            }
            boolean outermost = position == 0;
            long remaining = der.length - header.contentStart();
            // The slack, the size of the CRL, keeps the short reads that DSS accepts.
            long limit = remaining + der.length;
            if (!outermost && header.length() > limit) {
                return Optional.of("the element at offset " + position + " declares more than " + limit
                        + " bytes: the " + remaining + " bytes that remain, plus the size of the CRL");
            }
            if (outermost || header.constructed() || header.length() < 0) {
                pending.push(header.contentStart());
            }
            if (!outermost && header.length() >= 0) {
                pending.push((int) Math.min(header.contentStart() + header.length(), der.length));
            }
        }
        return Optional.empty();
    }

    /**
     * The identifier and length octets of an element.
     *
     * @param constructed whether bit 6 of the leading identifier octet is set (clause 8.1.2.5)
     * @param length the length, -1 for the indefinite form; any length above
     *        {@link Integer#MAX_VALUE} is kept just above it
     * @param contentStart the offset of the first contents octet
     */
    private record Header(boolean constructed, long length, int contentStart) {

        /** Reads the octets at a position, or returns {@code null} when they are incomplete or reserved. */
        static Header read(byte[] der, int start) {
            int position = start;
            int leading = der[position++] & 0xff;
            if ((leading & 0x1f) == 0x1f) {
                // Clause 8.1.2.4.2: subsequent octets, the last one with bit 8 set to zero.
                while (true) {
                    if (position >= der.length) {
                        return null;
                    }
                    if ((der[position++] & 0x80) == 0) {
                        break;
                    }
                }
            }
            if (position >= der.length) {
                return null;
            }
            int initial = der[position++] & 0xff;
            long length;
            if (initial < 0x80) {
                length = initial;
            } else if (initial == 0x80) {
                length = -1;
            } else if (initial == 0xff) {
                return null;
            } else {
                int count = initial & 0x7f;
                length = 0;
                for (int i = 0; i < count; i++) {
                    if (position >= der.length) {
                        return null;
                    }
                    length = Math.min((length << 8) | (der[position++] & 0xff), Integer.MAX_VALUE + 1L);
                }
            }
            return new Header((leading & 0x20) != 0, length, position);
        }
    }
}
