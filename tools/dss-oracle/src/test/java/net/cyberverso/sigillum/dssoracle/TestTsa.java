package net.cyberverso.sigillum.dssoracle;

import java.io.StringReader;
import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

/**
 * A stand-in for {@code sigillum-testpki tsa} in the tests of the sign mode,
 * run as a separate program with the same command line: {@code tsa
 * --digest-algorithm=<name> --digest=<hex> --time=<time> --tsa-key=<file>
 * --tsa-cert=<file>}. It writes a timestamp token in DER to standard output,
 * with the given time as its genTime, signed with deterministic ECDSA, so
 * that two identical requests give the same token. The tests use it so that
 * {@code mvn verify} needs no Rust build; the signed-corpus workflow runs
 * the sign mode with {@code sigillum-testpki} itself.
 */
public final class TestTsa {

    /** The policy of the test timestamping authority, as in testdata/README.md. */
    private static final String POLICY = "1.3.6.1.4.1.32473.1.2";

    private TestTsa() {
    }

    /**
     * The content type and message digest only, without the signing time
     * that Bouncy Castle adds by default from the clock, as
     * {@code sigillum-testpki tsa} issues them.
     */
    private static AttributeTable signedAttributes(Map<?, ?> parameters) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(CMSAttributes.contentType,
                new DERSet((ASN1ObjectIdentifier) parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE))));
        attributes.add(new Attribute(CMSAttributes.messageDigest,
                new DERSet(new DEROctetString((byte[]) parameters.get(CMSAttributeTableGenerator.DIGEST)))));
        return new AttributeTable(attributes);
    }

    /** ECDSA with SHA-256 and the deterministic nonces of RFC 6979, from Bouncy Castle. */
    private static final class DeterministicEcdsa implements ContentSigner {
        private final ByteArrayOutputStream data = new ByteArrayOutputStream();
        private final PrivateKey key;

        DeterministicEcdsa(PrivateKey key) {
            this.key = key;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        }

        @Override
        public OutputStream getOutputStream() {
            return data;
        }

        @Override
        public byte[] getSignature() {
            try {
                Signature signature = Signature.getInstance("SHA256withECDDSA", "BC");
                signature.initSign(key);
                signature.update(data.toByteArray());
                return signature.sign();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * Issues one token.
     *
     * @param args the command line
     * @throws Exception if the token cannot be issued
     */
    public static void main(String[] args) throws Exception {
        Map<String, String> options = new LinkedHashMap<>();
        if (args.length == 0 || !args[0].equals("tsa")) {
            System.err.println("usage: tsa --digest-algorithm=<name> --digest=<hex> --time=<time> "
                    + "--tsa-key=<file> --tsa-cert=<file>");
            System.exit(2);
        }
        // Every option comes as one argument, --name=value, as the sign mode passes them.
        for (int i = 1; i < args.length; i++) {
            int equals = args[i].indexOf('=');
            if (!args[i].startsWith("--") || equals < 0) {
                System.err.println("unexpected argument: " + args[i]);
                System.exit(2);
            }
            options.put(args[i].substring(0, equals), args[i].substring(equals + 1));
        }
        ASN1ObjectIdentifier algorithm = switch (options.get("--digest-algorithm")) {
            case "SHA-256" -> NISTObjectIdentifiers.id_sha256;
            case "SHA-384" -> NISTObjectIdentifiers.id_sha384;
            case "SHA-512" -> NISTObjectIdentifiers.id_sha512;
            default -> null;
        };
        if (algorithm == null) {
            System.err.println("unsupported digest algorithm");
            System.exit(2);
        }
        byte[] digest = HexFormat.of().parseHex(options.get("--digest"));
        Instant time = Instant.parse(options.get("--time"));
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey key;
        try (PEMParser parser = new PEMParser(new StringReader(
                Files.readString(Path.of(options.get("--tsa-key")), StandardCharsets.US_ASCII)))) {
            key = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) parser.readObject());
        }
        X509Certificate certificate;
        try (PEMParser parser = new PEMParser(new StringReader(
                Files.readString(Path.of(options.get("--tsa-cert")), StandardCharsets.US_ASCII)))) {
            certificate = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) parser.readObject());
        }
        TimeStampTokenGenerator generator = new TimeStampTokenGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                        .setSignedAttributeGenerator(TestTsa::signedAttributes)
                        .build(new DeterministicEcdsa(key), certificate),
                new JcaDigestCalculatorProviderBuilder().build()
                        .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                new ASN1ObjectIdentifier(POLICY));
        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add(certificate);
        generator.addCertificates(new JcaCertStore(certificates));
        TimeStampRequestGenerator request = new TimeStampRequestGenerator();
        request.setCertReq(true);
        BigInteger serial = new BigInteger(1, MessageDigest.getInstance("SHA-256")
                .digest((options.get("--digest") + options.get("--time")).getBytes(StandardCharsets.US_ASCII)));
        byte[] token = generator.generate(request.generate(algorithm, digest), serial, Date.from(time))
                .getEncoded();
        System.out.write(token, 0, token.length);
        System.out.flush();
    }
}
