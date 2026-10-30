package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

/**
 * Checks the nesting depth of the JSON that DSS parses in a JWS, before DSS
 * parses it. DSS 6.5.1 validates that JSON against the JAdES schema with
 * json-sKema 0.32.0, whose parser refuses a value nested more than
 * {@link #MAX_DEPTH} levels deep, counting each object and array, and DSS
 * then fails. Below that depth, other parsers of DSS recurse as deep, and
 * the stack of the worker ({@link ResourceLimits#STACK_BYTES}) holds them.
 * A document nested deeper is therefore rejected without being parsed.
 *
 * <p>The JSON checked is the JSON that DSS validates against the schema, at
 * the places that the JWS structure gives it:
 *
 * <ul>
 * <li>the document itself, when it is in the JSON serialisation of RFC 7515,
 * section 7.2, which starts with an opening brace;</li>
 * <li>the JWS Protected Headers: the member {@code protected} of each element
 * of {@code signatures} in the general syntax (section 7.2.1), or, when the
 * document has no {@code signatures}, the member {@code protected} of the
 * document in the flattened syntax (section 7.2.2). DSS ignores the
 * members of the flattened syntax when {@code signatures} is present, and
 * skips an element of {@code signatures}, or the flattened document, whose
 * member {@code signature} is absent, null or a blank string, with all its
 * headers;</li>
 * <li>the components of the header parameter {@code etsiU} of ETSI TS
 * 119 182-1 V1.2.1, clause 5.3.1, in the JWS Unprotected Header,
 * {@code header}, at the same places, when every component of the array is
 * a string of base64url characters. DSS then decodes them, puts them in an
 * object {@code {"etsiU":[...]}} and validates that object, so a component
 * counts two levels deeper. Otherwise DSS does not validate them against the
 * schema;</li>
 * <li>the counter signatures, the values of the members {@code cSig} of the
 * etsiU components (clause 5.3.2), encoded or clear: DSS parses each as a
 * JWS, a string as it is or an object as its JSON text, and checks it as a
 * document of its own, with its own counter signatures in turn. As DSS
 * selects components ({@code DSSJsonUtils.parseEtsiUComponent}), a clear
 * component counts only when it has one member, and an encoded one only by
 * its first member;</li>
 * <li>the JWS Protected Header of a JWS in the compact serialisation of RFC
 * 7515, section 7.1: the part before the first full stop.</li>
 * </ul>
 *
 * Member names and string values are read with their JSON escapes decoded
 * (RFC 8259, section 7), and the encoded parts are decoded from base64url as
 * DSS decodes them, with {@code DSSJsonUtils.fromBase64Url}, which skips
 * characters outside the alphabet. A member of the same name elsewhere, such
 * as a {@code protected} member of a header parameter, is not decoded: DSS
 * does not parse it as a header.
 *
 * <p>The walk of each JSON text reads each octet once and keeps a record of
 * the open containers down to {@link #NAMED_DEPTH} levels only, counting
 * those below, so its memory does not grow with the depth. Counter
 * signatures are checked from a work list, not by recursion. Each is a copy
 * of part of the text that holds it, or of its decoded form, and is walked
 * again as a document of its own, so a counter signature nested k levels
 * deep in others is read k + 1 times: the time and memory grow with the
 * input and its decoded parts times the nesting of counter signatures. It
 * is not a validating parser: malformed JSON is left to DSS. A
 * refusal of json-sKema that the walk does not foresee is attributed to the
 * document by {@link #isDepthLimitOfDss}.
 */
final class JsonDepth {

    /** The largest depth that the JSON schema validator of DSS accepts. */
    static final int MAX_DEPTH = 100_000;

    /** The levels that DSS adds around an etsiU component: the object and the array {@code {"etsiU":[...]}}. */
    private static final int ETSI_U_LEVELS = 2;
    /**
     * The deepest place that the walk names, in containers: the object of a
     * counter signature in a clear etsiU component of an element of
     * {@code signatures}.
     */
    private static final int NAMED_DEPTH = 7;

    /**
     * A step into an array element in a path. Paths are lists of member
     * names and this token, so that a member whose name contains a solidus
     * or a number sign is never taken for a place of the structure.
     */
    private static final Object ELEMENT = new Object();
    private static final List<Object> PROTECTED = List.of("protected");
    private static final List<Object> SIGNATURE_PROTECTED = List.of("signatures", ELEMENT, "protected");
    private static final List<Object> ETSI_U = List.of("header", "etsiU");
    private static final List<Object> SIGNATURE_ETSI_U = List.of("signatures", ELEMENT, "header", "etsiU");
    private static final List<Object> CSIG = List.of("header", "etsiU", ELEMENT, "cSig");
    private static final List<Object> SIGNATURE_CSIG =
            List.of("signatures", ELEMENT, "header", "etsiU", ELEMENT, "cSig");
    private static final List<Object> COMPONENT_CSIG = List.of("cSig");
    private static final List<Object> SIGNATURE_ENTRY = List.of("signatures", ELEMENT);

    private JsonDepth() {
    }

    /**
     * Checks a document.
     *
     * @param document the document
     * @return the problem, or empty when every JSON part is within the limit
     *         or the document is not a JWS
     */
    static Optional<String> check(byte[] document) {
        Deque<byte[]> pending = new ArrayDeque<>();
        pending.add(document);
        boolean counterSignature = false;
        while (!pending.isEmpty()) {
            Optional<String> problem = checkOne(pending.poll(), counterSignature, pending);
            if (problem.isPresent()) {
                return problem;
            }
            counterSignature = true;
        }
        return Optional.empty();
    }

    /** Checks one JWS, and adds its counter signatures to the work list. */
    private static Optional<String> checkOne(byte[] document, boolean counterSignature, Deque<byte[]> pending) {
        String of = counterSignature ? "a counter signature" : "the document";
        int start = 0;
        while (start < document.length && whitespace(document[start])) {
            start++;
        }
        if (start < document.length && document[start] == '{') {
            Walk walk = walk(document, false);
            if (walk.depth > MAX_DEPTH) {
                return Optional.of(problem(of, walk.depth));
            }
            for (Encoded header : walk.protectedHeaders) {
                if (header.topLevel() && walk.hasSignatures || !header.entry().read) {
                    continue;
                }
                Walk decoded = decoded(header.value());
                if (decoded != null && decoded.depth > MAX_DEPTH) {
                    return Optional.of(problem("a protected header of " + of, decoded.depth));
                }
            }
            for (EtsiU array : walk.etsiU) {
                if (array.topLevel && walk.hasSignatures || !array.entry.read) {
                    continue;
                }
                for (String component : array.strings) {
                    if (!strict(component)) {
                        continue;
                    }
                    // DSS decodes a component of base64url characters wherever it reads it.
                    Walk decoded = decoded(component);
                    if (decoded == null) {
                        continue;
                    }
                    if (array.allStrict && decoded.depth + ETSI_U_LEVELS > MAX_DEPTH) {
                        return Optional.of(problem("an etsiU component of " + of + ", with the two levels of"
                                + " the etsiU object that DSS validates", decoded.depth + ETSI_U_LEVELS));
                    }
                    pending.addAll(decoded.counterSignatures);
                }
                pending.addAll(array.counterSignatures);
            }
            return Optional.empty();
        }
        String header = compactHeader(document);
        if (header == null) {
            return Optional.empty();
        }
        Walk decoded = decoded(header);
        return decoded != null && decoded.depth > MAX_DEPTH
                ? Optional.of(problem("the protected header of " + of, decoded.depth)) : Optional.empty();
    }

    /**
     * Reports whether the document is a JWS as DSS recognises one, in the
     * JSON serialisation (starting with an opening brace after white space)
     * or in the compact serialisation ({@link #compactHeader}).
     *
     * @param document the document
     * @return whether DSS may parse it as a JWS
     */
    static boolean isJws(byte[] document) {
        int start = 0;
        while (start < document.length && whitespace(document[start])) {
            start++;
        }
        return start < document.length && document[start] == '{' || compactHeader(document) != null;
    }

    /**
     * Reports whether an exception of DSS is the refusal of the JSON schema
     * validator of DSS, json-sKema, to parse JSON nested deeper than
     * {@link #MAX_DEPTH}: a {@code TooDeeplyNestedValueException}, thrown or
     * among the causes.
     *
     * @param exception the exception
     * @return whether it is that refusal
     */
    static boolean isDepthLimitOfDss(Throwable exception) {
        int depth = 0;
        for (Throwable current = exception; current != null && depth < 16; current = current.getCause(), depth++) {
            if (current instanceof com.github.erosb.jsonsKema.TooDeeplyNestedValueException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the part before the first full stop when the document may be
     * a JWS in the compact serialisation, as DSS recognises one: the header
     * is made of base64url characters, and line breaks may end the
     * document. Returns {@code null} otherwise.
     */
    private static String compactHeader(byte[] document) {
        int dot = -1;
        for (int i = 0; i < document.length; i++) {
            if (document[i] == '.') {
                dot = i;
                break;
            }
            if (!base64url(document[i])) {
                return null;
            }
        }
        return dot <= 0 ? null : new String(document, 0, dot, StandardCharsets.US_ASCII);
    }

    /** Decodes a base64url value as DSS does, and walks it as an etsiU component; null if it does not decode. */
    private static Walk decoded(String encoded) {
        byte[] bytes;
        try {
            bytes = DSSJsonUtils.fromBase64Url(encoded);
        } catch (RuntimeException e) {
            // DSS fails on it too, when it decodes it; that is left to DSS.
            return null;
        }
        return walk(bytes, true);
    }

    /** Whether a string has only base64url characters, as DSS requires of an etsiU component that it decodes. */
    private static boolean strict(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c > 0x7f || !base64url((byte) c)) {
                return false;
            }
        }
        return true;
    }

    private static String problem(String what, int depth) {
        return "the JSON of " + what + " is nested " + depth + " levels deep; the JSON schema validator of DSS"
                + " (json-sKema 0.32.0) accepts at most " + MAX_DEPTH;
    }

    private static boolean base64url(byte b) {
        return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_';
    }

    private static boolean whitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    /**
     * A protected header found in a document, whether it is at the top level,
     * of the flattened syntax, and the signature entry that holds it.
     */
    private record Encoded(String value, boolean topLevel, Entry entry) {
    }

    /**
     * A signature of the document: the document in the flattened syntax, or
     * an element of {@code signatures} in the general syntax. DSS skips one
     * whose member {@code signature} is absent, null or a blank string, and
     * does not parse its headers (JWSJsonSerializationParser of dss-jades).
     */
    private static final class Entry {
        /** Whether DSS reads the entry: its signature is another value. */
        boolean read;
    }

    /** An etsiU array found in a document. */
    private static final class EtsiU {
        final boolean topLevel;
        final Entry entry;
        final List<String> strings = new ArrayList<>();
        boolean allStrict = true;
        final List<byte[]> counterSignatures = new ArrayList<>();

        EtsiU(boolean topLevel, Entry entry) {
            this.topLevel = topLevel;
            this.entry = entry;
        }
    }

    /** What the walk of one JSON text found. */
    private static final class Walk {
        int depth;
        boolean hasSignatures;
        final List<Encoded> protectedHeaders = new ArrayList<>();
        final List<EtsiU> etsiU = new ArrayList<>();
        /** In an etsiU component, the counter signatures of its member cSig. */
        final List<byte[]> counterSignatures = new ArrayList<>();
    }

    /** An open object or array. */
    private static final class Frame {
        final boolean object;
        /** In an object, the decoded name of the current member, when the frame is shallow enough to need it. */
        String key;
        boolean expectingKey;
        /** For an etsiU array, its record. */
        EtsiU etsiU;
        /** In an object, the number of members read so far. */
        int members;
        /** For a clear etsiU component, its counter signatures, kept if the component has one member only. */
        List<byte[]> pendingCounterSignatures;
        /** For a counter signature given as an object, the offset of its opening brace, and where it goes. */
        int captureStart = -1;
        List<byte[]> captureInto;
        /** For a signature entry, its record. */
        Entry entry;
        /** In an object, whether the value of the current member has started. */
        boolean valueStarted;

        Frame(boolean object) {
            this.object = object;
            this.expectingKey = object;
        }
    }

    /**
     * Walks a JSON text: a document, or, with {@code component}, a decoded
     * etsiU component, whose member {@code cSig} is a counter signature.
     */
    private static Walk walk(byte[] json, boolean component) {
        Walk walk = new Walk();
        Deque<Frame> frames = new ArrayDeque<>();
        // The containers open below the deepest frame kept: nothing in them is at a place that the walk names, so
        // they are counted, not recorded, and the walk keeps no more than NAMED_DEPTH frames however deep the JSON.
        int deep = 0;
        int i = 0;
        while (i < json.length) {
            byte b = json[i];
            if (deep > 0) {
                switch (b) {
                    case '{', '[' -> {
                        deep++;
                        walk.depth = Math.max(walk.depth, NAMED_DEPTH + deep);
                    }
                    case '}', ']' -> deep--;
                    case '"' -> i = endOfString(json, i);
                    default -> {
                        // Nothing below the frames kept is at a place that the walk names.
                    }
                }
                i++;
                continue;
            }
            switch (b) {
                case '{', '[' -> {
                    elementOfEtsiU(frames, false);
                    valueStarts(frames, false);
                    if (frames.size() >= NAMED_DEPTH) {
                        deep++;
                        walk.depth = Math.max(walk.depth, NAMED_DEPTH + deep);
                        i++;
                        continue;
                    }
                    List<Object> path = path(frames);
                    Frame frame = new Frame(b == '{');
                    if (!component && b == '{' && (frames.isEmpty() || path.equals(SIGNATURE_ENTRY))) {
                        frame.entry = new Entry();
                    }
                    if (!component && b == '['
                            && (path.equals(ETSI_U) || path.equals(SIGNATURE_ETSI_U))) {
                        frame.etsiU = new EtsiU(path.equals(ETSI_U), entryOf(frames));
                        walk.etsiU.add(frame.etsiU);
                    }
                    if (b == '{') {
                        List<byte[]> target = counterSignatureTarget(walk, frames, path, component);
                        if (target != null) {
                            frame.captureStart = i;
                            frame.captureInto = target;
                        }
                    }
                    frames.push(frame);
                    walk.depth = Math.max(walk.depth, frames.size());
                    i++;
                }
                case '}', ']' -> {
                    if (!frames.isEmpty()) {
                        Frame frame = frames.pop();
                        if (frame.captureStart >= 0) {
                            frame.captureInto.add(Arrays.copyOfRange(json, frame.captureStart, i + 1));
                        }
                        // DSS ignores a clear etsiU component with more than one member (parseEtsiUComponent).
                        if (frame.pendingCounterSignatures != null && frame.members == 1 && !frames.isEmpty()
                                && frames.peek().etsiU != null) {
                            frames.peek().etsiU.counterSignatures.addAll(frame.pendingCounterSignatures);
                        }
                    }
                    i++;
                }
                case ',' -> {
                    if (!frames.isEmpty() && frames.peek().object) {
                        frames.peek().expectingKey = true;
                    }
                    i++;
                }
                case '"' -> {
                    int end = endOfString(json, i);
                    int stop = Math.min(end, json.length);
                    Frame frame = frames.peek();
                    boolean named = frames.size() <= NAMED_DEPTH;
                    if (frame != null && frame.object && frame.expectingKey) {
                        frame.key = named ? unescape(json, i + 1, stop) : null;
                        frame.expectingKey = false;
                        frame.valueStarted = false;
                        frame.members++;
                        if (!component && frames.size() == 1 && "signatures".equals(frame.key)) {
                            walk.hasSignatures = true;
                        }
                    } else if (frame != null && named) {
                        String value = unescape(json, i + 1, stop);
                        // DSS skips an entry whose signature is a blank string (Utils.isStringBlank).
                        valueStarts(frames, value.isBlank());
                        value(walk, frames, value, component);
                    }
                    i = end + 1;
                }
                default -> {
                    if (!whitespace(b) && b != ':') {
                        // A number, true, false or null: an element of an etsiU array that is not a string.
                        elementOfEtsiU(frames, false);
                        // DSS skips an entry whose signature is null.
                        valueStarts(frames, b == 'n');
                    }
                    i++;
                }
            }
        }
        return walk;
    }

    /** The offset of the quotation mark that ends the string starting at an offset, or the length of the text. */
    private static int endOfString(byte[] json, int start) {
        int end = start + 1;
        while (end < json.length && json[end] != '"') {
            end += json[end] == '\\' ? 2 : 1;
        }
        return end;
    }

    /**
     * Records the start of a value in the innermost container. When that
     * container is a signature entry and the value is that of its member
     * {@code signature}, DSS reads the entry unless the value is null or a
     * blank string. Of duplicate members, on which DSS fails, any value
     * that DSS would read counts.
     */
    private static void valueStarts(Deque<Frame> frames, boolean skipped) {
        Frame frame = frames.peek();
        if (frame == null || !frame.object || frame.expectingKey || frame.valueStarted) {
            return;
        }
        frame.valueStarted = true;
        if (frame.entry != null && "signature".equals(frame.key) && !skipped) {
            frame.entry.read = true;
        }
    }

    /** The signature entry that holds the innermost container: the nearest frame with one. */
    private static Entry entryOf(Deque<Frame> frames) {
        for (Frame frame : frames) {
            if (frame.entry != null) {
                return frame.entry;
            }
        }
        return null;
    }

    /** Records an element of an etsiU array that is not a string, which stops DSS decoding the array. */
    private static void elementOfEtsiU(Deque<Frame> frames, boolean string) {
        Frame frame = frames.peek();
        if (frame != null && frame.etsiU != null && !string) {
            frame.etsiU.allStrict = false;
        }
    }

    /** Records a string value at a place that the walk names. */
    private static void value(Walk walk, Deque<Frame> frames, String value, boolean component) {
        Frame frame = frames.peek();
        List<Object> path = path(frames);
        if (!component && path.equals(PROTECTED)) {
            walk.protectedHeaders.add(new Encoded(value, true, frame.entry));
        } else if (!component && path.equals(SIGNATURE_PROTECTED)) {
            walk.protectedHeaders.add(new Encoded(value, false, frame.entry));
        } else if (frame.etsiU != null) {
            frame.etsiU.strings.add(value);
            frame.etsiU.allStrict &= strict(value);
        } else {
            List<byte[]> target = counterSignatureTarget(walk, frames, path, component);
            if (target != null) {
                target.add(value.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * Returns where a counter signature at a path goes, or {@code null} when
     * the path is not that of a member cSig of an etsiU component: in a
     * decoded component, the member cSig of the component; in a document,
     * the member cSig of a clear component of an etsiU array.
     */
    private static List<byte[]> counterSignatureTarget(Walk walk, Deque<Frame> frames, List<Object> path,
            boolean component) {
        if (component) {
            // DSS reads only the first member of an encoded etsiU component.
            return path.equals(COMPONENT_CSIG) && frames.peek().members == 1 ? walk.counterSignatures : null;
        }
        if (!path.equals(CSIG) && !path.equals(SIGNATURE_CSIG)) {
            return null;
        }
        // The innermost frame is the clear component; its counter signatures count when it closes with one member.
        Frame clear = frames.peek();
        if (clear.pendingCounterSignatures == null) {
            clear.pendingCounterSignatures = new ArrayList<>();
        }
        return clear.pendingCounterSignatures;
    }

    /** The path of the current value, from the outermost container: member names, and {@link #ELEMENT}. */
    private static List<Object> path(Deque<Frame> frames) {
        List<Object> path = new ArrayList<>(frames.size());
        for (Iterator<Frame> outward = frames.descendingIterator(); outward.hasNext();) {
            Frame frame = outward.next();
            path.add(frame.object ? String.valueOf(frame.key) : ELEMENT);
        }
        return path;
    }

    /** Decodes the escapes of a JSON string (RFC 8259, section 7); a malformed escape is kept as it is. */
    private static String unescape(byte[] json, int from, int to) {
        String raw = new String(json, from, to - from, StandardCharsets.UTF_8);
        if (raw.indexOf('\\') < 0) {
            return raw;
        }
        StringBuilder text = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c != '\\' || i + 1 >= raw.length()) {
                text.append(c);
                continue;
            }
            char next = raw.charAt(++i);
            switch (next) {
                case 'b' -> text.append('\b');
                case 'f' -> text.append('\f');
                case 'n' -> text.append('\n');
                case 'r' -> text.append('\r');
                case 't' -> text.append('\t');
                case 'u' -> {
                    if (i + 4 < raw.length() && raw.substring(i + 1, i + 5).matches("[0-9A-Fa-f]{4}")) {
                        text.append((char) Integer.parseInt(raw.substring(i + 1, i + 5), 16));
                        i += 4;
                    } else {
                        text.append("\\u");
                    }
                }
                default -> text.append(next);
            }
        }
        return text.toString();
    }
}
