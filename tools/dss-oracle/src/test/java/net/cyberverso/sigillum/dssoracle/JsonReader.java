package net.cyberverso.sigillum.dssoracle;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict reader of JSON (RFC 8259) for the tests. Objects become ordered
 * maps, arrays lists, numbers longs, and {@code null} becomes {@code null}.
 * Duplicate member names, trailing data and unescaped control characters are
 * refused.
 */
final class JsonReader {

    private final String text;
    private int position;

    private JsonReader(String text) {
        this.text = text;
    }

    static Object read(String text) {
        JsonReader reader = new JsonReader(text);
        reader.whitespace();
        Object value = reader.value();
        reader.whitespace();
        if (reader.position != text.length()) {
            throw reader.error("trailing data");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(String text) {
        return (Map<String, Object>) read(text);
    }

    private Object value() {
        if (position >= text.length()) {
            throw error("unexpected end");
        }
        char c = text.charAt(position);
        return switch (c) {
            case '{' -> objectValue();
            case '[' -> arrayValue();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> objectValue() {
        Map<String, Object> members = new LinkedHashMap<>();
        position++;
        whitespace();
        if (peek('}')) {
            position++;
            return members;
        }
        while (true) {
            whitespace();
            String name = string();
            whitespace();
            expect(':');
            whitespace();
            if (members.containsKey(name)) {
                throw error("duplicate member " + name);
            }
            members.put(name, value());
            whitespace();
            if (peek(',')) {
                position++;
                continue;
            }
            expect('}');
            return members;
        }
    }

    private List<Object> arrayValue() {
        List<Object> elements = new ArrayList<>();
        position++;
        whitespace();
        if (peek(']')) {
            position++;
            return elements;
        }
        while (true) {
            whitespace();
            elements.add(value());
            whitespace();
            if (peek(',')) {
                position++;
                continue;
            }
            expect(']');
            return elements;
        }
    }

    private String string() {
        expect('"');
        StringBuilder builder = new StringBuilder();
        while (true) {
            if (position >= text.length()) {
                throw error("unterminated string");
            }
            char c = text.charAt(position++);
            if (c == '"') {
                return builder.toString();
            }
            if (c < 0x20) {
                throw error("unescaped control character");
            }
            if (c != '\\') {
                builder.append(c);
                continue;
            }
            char escape = text.charAt(position++);
            switch (escape) {
                case '"' -> builder.append('"');
                case '\\' -> builder.append('\\');
                case '/' -> builder.append('/');
                case 'b' -> builder.append('\b');
                case 'f' -> builder.append('\f');
                case 'n' -> builder.append('\n');
                case 'r' -> builder.append('\r');
                case 't' -> builder.append('\t');
                case 'u' -> {
                    builder.append((char) Integer.parseInt(text.substring(position, position + 4), 16));
                    position += 4;
                }
                default -> throw error("invalid escape");
            }
        }
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, position)) {
            throw error("invalid literal");
        }
        position += word.length();
        return value;
    }

    private Long number() {
        int start = position;
        if (peek('-')) {
            position++;
        }
        while (position < text.length() && Character.isDigit(text.charAt(position))) {
            position++;
        }
        if (start == position) {
            throw error("unexpected character");
        }
        return Long.parseLong(text.substring(start, position));
    }

    private void whitespace() {
        while (position < text.length() && " \t\r\n".indexOf(text.charAt(position)) >= 0) {
            position++;
        }
    }

    private boolean peek(char c) {
        return position < text.length() && text.charAt(position) == c;
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw error("expected " + c);
        }
        position++;
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException(message + " at offset " + position);
    }
}
