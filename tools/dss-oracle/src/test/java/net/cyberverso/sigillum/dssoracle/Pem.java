package net.cyberverso.sigillum.dssoracle;

import java.util.Base64;

/** Converts between PEM (RFC 7468) and DER for the tests. */
final class Pem {

    private Pem() {
    }

    /** Returns the DER content of the first PEM block of a text. */
    static byte[] decode(String pem) {
        int begin = pem.indexOf('\n', pem.indexOf("-----BEGIN ")) + 1;
        int end = pem.indexOf("-----END ");
        return Base64.getMimeDecoder().decode(pem.substring(begin, end));
    }

    /** Returns a PEM block with the given label. */
    static String encode(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                        .encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }
}
