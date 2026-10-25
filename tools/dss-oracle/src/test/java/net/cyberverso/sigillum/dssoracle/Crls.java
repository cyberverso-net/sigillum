package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificateList;

/** Derives CRLs from the corpus for the tests. */
final class Crls {

    private static final Path TESTDATA = Path.of("..", "..", "testdata");

    private Crls() {
    }

    /**
     * Returns crl/ca-ecdsa with the SEQUENCE of its crlExtensions [0] in the
     * indefinite length form, ended by two zero octets (X.690, clauses 8.1.3.6
     * and 8.1.5), signed again by the key of pki/ca-ecdsa.
     */
    static byte[] caEcdsaWithIndefiniteExtensions() throws Exception {
        java.util.List<byte[]> components = tbsComponents();
        byte[] tagged = components.get(components.size() - 1);
        byte[] extensions = contents(tagged);
        byte[] indefinite = concat(new byte[] {0x30, (byte) 0x80}, contents(extensions), new byte[] {0, 0});
        components.set(components.size() - 1, tlv(0xa0, indefinite));
        return signed(tlv(0x30, concat(components.toArray(byte[][]::new))));
    }

    /**
     * Returns crl/ca-ecdsa with its first revoked certificate entry in the
     * indefinite length form, ended by two zero octets, signed again by the
     * key of pki/ca-ecdsa.
     */
    static byte[] caEcdsaWithIndefiniteEntry() throws Exception {
        java.util.List<byte[]> components = tbsComponents();
        int revoked = components.size() - 2;
        java.util.List<byte[]> entries = elements(contents(components.get(revoked)));
        entries.set(0, concat(new byte[] {0x30, (byte) 0x80}, contents(entries.get(0)), new byte[] {0, 0}));
        components.set(revoked, tlv(0x30, concat(entries.toArray(byte[][]::new))));
        return signed(tlv(0x30, concat(components.toArray(byte[][]::new))));
    }

    /**
     * Returns crl/ca-ecdsa with the length octets of the element at an offset
     * replaced by the long form of a length, the rest unchanged.
     */
    static byte[] caEcdsaWithLength(int offset, long length) throws Exception {
        byte[] crl = Files.readAllBytes(TESTDATA.resolve("crl/ca-ecdsa.crl"));
        int lengthAt = offset + 1;
        int initial = crl[lengthAt] & 0xff;
        int octets = initial < 0x80 ? 1 : 1 + (initial & 0x7f);
        byte[] replacement = {(byte) 0x84, (byte) (length >>> 24), (byte) (length >>> 16), (byte) (length >>> 8),
            (byte) length};
        return concat(java.util.Arrays.copyOf(crl, lengthAt), replacement,
                java.util.Arrays.copyOfRange(crl, lengthAt + octets, crl.length));
    }

    /** Returns the offsets of the identifier octets of every element of crl/ca-ecdsa, in DER. */
    static java.util.List<Integer> caEcdsaElementOffsets() throws Exception {
        byte[] crl = Files.readAllBytes(TESTDATA.resolve("crl/ca-ecdsa.crl"));
        java.util.List<Integer> offsets = new java.util.ArrayList<>();
        collect(crl, 0, crl.length, offsets);
        return offsets;
    }

    private static void collect(byte[] der, int start, int end, java.util.List<Integer> offsets) {
        int position = start;
        while (position < end) {
            offsets.add(position);
            int header = headerLength(der, position);
            int length = contentLength(der, position);
            if ((der[position] & 0x20) != 0) {
                collect(der, position + header, position + header + length, offsets);
            }
            position += header + length;
        }
    }

    private static java.util.List<byte[]> tbsComponents() throws Exception {
        byte[] crl = Files.readAllBytes(TESTDATA.resolve("crl/ca-ecdsa.crl"));
        byte[] tbs = elements(contents(crl)).get(0);
        return elements(contents(tbs));
    }

    private static byte[] signed(byte[] tbs) throws Exception {
        CertificateList original = CertificateList.getInstance(
                Files.readAllBytes(TESTDATA.resolve("crl/ca-ecdsa.crl")));
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(
                Pem.decode(Files.readString(TESTDATA.resolve("pki/keys/ca-ecdsa.test-key.pem")))));
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(36);
        Signature signer = Signature.getInstance("SHA384withECDSA");
        signer.initSign(key, random);
        signer.update(tbs);
        byte[] algorithm = original.getSignatureAlgorithm().getEncoded(ASN1Encoding.DER);
        byte[] value = new DERBitString(signer.sign()).getEncoded(ASN1Encoding.DER);
        return tlv(0x30, concat(tbs, algorithm, value));
    }

    /** The elements of DER contents, each with its identifier and length octets. */
    private static java.util.List<byte[]> elements(byte[] contents) {
        java.util.List<byte[]> elements = new java.util.ArrayList<>();
        int position = 0;
        while (position < contents.length) {
            int size = headerLength(contents, position) + contentLength(contents, position);
            elements.add(java.util.Arrays.copyOfRange(contents, position, position + size));
            position += size;
        }
        return elements;
    }

    private static byte[] contents(byte[] element) {
        return java.util.Arrays.copyOfRange(element, headerLength(element, 0), element.length);
    }

    private static int headerLength(byte[] der, int at) {
        int initial = der[at + 1] & 0xff;
        return 2 + (initial < 0x80 ? 0 : initial & 0x7f);
    }

    private static int contentLength(byte[] der, int at) {
        int initial = der[at + 1] & 0xff;
        if (initial < 0x80) {
            return initial;
        }
        int length = 0;
        for (int i = 0; i < (initial & 0x7f); i++) {
            length = (length << 8) | (der[at + 2 + i] & 0xff);
        }
        return length;
    }

    private static byte[] tlv(int tag, byte[] contents) {
        int length = contents.length;
        byte[] header = length < 0x80 ? new byte[] {(byte) tag, (byte) length}
                : length < 0x100 ? new byte[] {(byte) tag, (byte) 0x81, (byte) length}
                : new byte[] {(byte) tag, (byte) 0x82, (byte) (length >>> 8), (byte) length};
        return concat(header, contents);
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int position = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, position, part.length);
            position += part.length;
        }
        return result;
    }

    /**
     * Returns crl/ca-ecdsa with the same TBSCertList, signed again by the key
     * of pki/ca-ecdsa with ECDSA and SHA-384 until the encoding of the
     * signature ends with a zero octet. The random numbers come from a seeded
     * SHA1PRNG, so the result is the same on every call.
     */
    static byte[] caEcdsaSignatureEndingInZero() throws Exception {
        CertificateList original = CertificateList.getInstance(
                Files.readAllBytes(TESTDATA.resolve("crl/ca-ecdsa.crl")));
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(
                Pem.decode(Files.readString(TESTDATA.resolve("pki/keys/ca-ecdsa.test-key.pem")))));
        byte[] tbs = original.getTBSCertList().getEncoded(ASN1Encoding.DER);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(36);
        for (int attempt = 0; attempt < 10_000; attempt++) {
            Signature signer = Signature.getInstance("SHA384withECDSA");
            signer.initSign(key, random);
            signer.update(tbs);
            byte[] signature = signer.sign();
            if (signature[signature.length - 1] == 0) {
                return new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    original.getTBSCertList(), original.getSignatureAlgorithm(), new DERBitString(signature)})
                        .getEncoded(ASN1Encoding.DER);
            }
        }
        throw new IllegalStateException("no signature ending with a zero octet");
    }
}
