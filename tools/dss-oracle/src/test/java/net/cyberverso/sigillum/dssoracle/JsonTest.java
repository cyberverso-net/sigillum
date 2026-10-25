package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void writesMembersInInsertionOrderWithAFixedLayout() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("flag", true);
        details.put("list", List.of("a", 2L));
        details.put("empty", List.of());
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("z", 1);
        value.put("a", null);
        value.put("details", details);
        value.put("none", Map.of());
        assertEquals("""
                {
                  "z": 1,
                  "a": null,
                  "details": {
                    "flag": true,
                    "list": [
                      "a",
                      2
                    ],
                    "empty": []
                  },
                  "none": {}
                }
                """, Json.write(value));
    }

    @Test
    void escapesQuotesBackslashesAndControlCharacters() {
        String text = "quote \" backslash \\ newline \n tab \t nul \u0000 unit \u001f delete \u007f é  ";
        String json = Json.write(Map.of("text", text));
        assertEquals(Map.of("text", text), JsonReader.read(json));
        assertEquals(0, json.chars().filter(c -> c < 0x20 && c != '\n').count(), json);
        assertEquals("{\n  \"text\": \"quote \\\" backslash \\\\ newline \\n tab \\t nul \\u0000 unit \\u001f"
                + " delete \u007f é  \"\n}\n", json);
    }

    @Test
    void roundTripsArbitraryStrings() {
        Random random = new Random(36);
        for (int i = 0; i < 2000; i++) {
            char[] chars = new char[random.nextInt(24)];
            for (int j = 0; j < chars.length; j++) {
                chars[j] = (char) random.nextInt(0x3000);
            }
            String text = new String(chars);
            assertEquals(Map.of("k" + text, text), JsonReader.read(Json.write(Map.of("k" + text, text))),
                    Arrays.toString(chars));
        }
    }

    @Test
    void refusesValuesItCannotWrite() {
        assertThrows(IllegalArgumentException.class, () -> Json.write(Map.of("x", 1.5)));
        assertThrows(IllegalArgumentException.class, () -> Json.write(Map.of("x", new Object())));
        Map<Object, Object> nonStringKey = new LinkedHashMap<>();
        nonStringKey.put(1, "x");
        assertThrows(IllegalArgumentException.class, () -> Json.write(nonStringKey));
    }
}
