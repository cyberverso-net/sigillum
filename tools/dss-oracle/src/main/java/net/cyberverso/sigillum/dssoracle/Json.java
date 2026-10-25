package net.cyberverso.sigillum.dssoracle;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Writes JSON text (RFC 8259) with a fixed layout, so that equal values give
 * equal bytes. Objects are maps with string keys, written in their iteration
 * order; arrays are lists. Strings, booleans, {@code Integer}, {@code Long}
 * and {@code null} are the only other values. Members are indented by two
 * spaces, one per line, and the text ends with a line feed.
 */
public final class Json {

    private Json() {
    }

    /**
     * Writes a value as JSON text.
     *
     * @param value the value
     * @return the JSON text, ending with a line feed
     * @throws IllegalArgumentException if the value holds anything that is not
     *         listed above, or a map key that is not a string
     */
    public static String write(Object value) {
        StringBuilder builder = new StringBuilder();
        value(builder, value, 0);
        return builder.append('\n').toString();
    }

    private static void value(StringBuilder builder, Object value, int depth) {
        switch (value) {
            case null -> builder.append("null");
            case String text -> string(builder, text);
            case Boolean flag -> builder.append(flag);
            case Integer number -> builder.append(number);
            case Long number -> builder.append(number);
            case Map<?, ?> map -> object(builder, map, depth);
            case List<?> list -> array(builder, list, depth);
            default -> throw new IllegalArgumentException("Not a JSON value: " + value.getClass().getName());
        }
    }

    private static void object(StringBuilder builder, Map<?, ?> map, int depth) {
        if (map.isEmpty()) {
            builder.append("{}");
            return;
        }
        builder.append('{');
        Iterator<? extends Map.Entry<?, ?>> entries = map.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<?, ?> entry = entries.next();
            if (!(entry.getKey() instanceof String name)) {
                throw new IllegalArgumentException("A JSON member name must be a string: " + entry.getKey());
            }
            newline(builder, depth + 1);
            string(builder, name);
            builder.append(": ");
            value(builder, entry.getValue(), depth + 1);
            if (entries.hasNext()) {
                builder.append(',');
            }
        }
        newline(builder, depth);
        builder.append('}');
    }

    private static void array(StringBuilder builder, List<?> list, int depth) {
        if (list.isEmpty()) {
            builder.append("[]");
            return;
        }
        builder.append('[');
        for (int i = 0; i < list.size(); i++) {
            newline(builder, depth + 1);
            value(builder, list.get(i), depth + 1);
            if (i + 1 < list.size()) {
                builder.append(',');
            }
        }
        newline(builder, depth);
        builder.append(']');
    }

    private static void newline(StringBuilder builder, int depth) {
        builder.append('\n').append("  ".repeat(depth));
    }

    /** RFC 8259, section 7: escapes the quotation mark, the reverse solidus and the control characters. */
    private static void string(StringBuilder builder, String text) {
        builder.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                default -> {
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    } else {
                        builder.append(c);
                    }
                }
            }
        }
        builder.append('"');
    }
}
