package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Tests of the attribution of a refusal of the JSON schema validator of DSS to the document. */
class JsonDepthTest {

    /** The refusal that json-sKema 0.32.0 gives for JSON nested deeper than it accepts, on the stack of the worker. */
    private static RuntimeException refusal() throws InterruptedException {
        String deep = "[".repeat(JsonDepth.MAX_DEPTH + 1) + "]".repeat(JsonDepth.MAX_DEPTH + 1);
        RuntimeException[] refusal = new RuntimeException[1];
        Thread thread = new Thread(null, () -> {
            try {
                new com.github.erosb.jsonsKema.JsonParser(deep, URI.create("urn:test")).parse();
            } catch (RuntimeException e) {
                refusal[0] = e;
            }
        }, "json-skema", ResourceLimits.STACK_BYTES);
        thread.start();
        thread.join();
        if (refusal[0] == null) {
            throw new AssertionError("json-sKema accepted JSON nested deeper than " + JsonDepth.MAX_DEPTH);
        }
        return refusal[0];
    }

    @Test
    void theRefusalOfJsonSkemaIsRecognisedAsItIsOrAsACause() throws InterruptedException {
        RuntimeException refusal = refusal();
        assertTrue(refusal instanceof com.github.erosb.jsonsKema.TooDeeplyNestedValueException, refusal.toString());
        assertTrue(JsonDepth.isDepthLimitOfDss(refusal));
        assertTrue(JsonDepth.isDepthLimitOfDss(new IllegalStateException("wrapped", refusal)));
    }

    @Test
    void otherFailuresAreNotRecognised() {
        assertFalse(JsonDepth.isDepthLimitOfDss(new IllegalArgumentException("too deeply nested")));
        assertFalse(JsonDepth.isDepthLimitOfDss(new StackOverflowError()));
        assertFalse(JsonDepth.isDepthLimitOfDss(new IllegalStateException("x", new NullPointerException())));
    }

    @Test
    void onlyAJwsIsADocumentWhoseJsonDssParses() {
        assertTrue(JsonDepth.isJws(" {\"payload\":\"e30\"}".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(JsonDepth.isJws("eyJhbGciOiJFUzI1NiJ9.e30.AAAA\n".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(JsonDepth.isJws("%PDF-1.7\n".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(JsonDepth.isJws(new byte[] {0x30, (byte) 0x82, 0x01, 0x00}));
        assertFalse(JsonDepth.isJws(new byte[0]));
    }
}
