package com.authenticity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON parser used by the Authenticity SDK.
 *
 * <p>It is intentionally small and tolerant: it parses the flat JSON objects
 * returned by the Authenticity API (string / number / boolean / array / object
 * values) and never throws on malformed input - unknown or missing keys
 * simply yield an empty string, mirroring the behaviour of the C++/C# SDKs.</p>
 */
public final class Json {

    private Json() {
    }

    /**
     * Parse a JSON document into a {@code Map<String, Object>}. Returns an
     * empty map if the text is not valid JSON.
     */
    public static Map<String, Object> parse(String text) {
        if (text == null) {
            return new HashMap<>();
        }
        Parser p = new Parser(text);
        try {
            Object value = p.parseValue();
            if (value instanceof Map) {
                return (Map<String, Object>) value;
            }
        } catch (Exception ignored) {
            // fall through - return empty
        }
        return new HashMap<>();
    }

    /**
     * Extract a raw value for a key; returns null when absent/unparsable.
     */
    public static Object get(Map<String, Object> obj, String key) {
        if (obj == null) {
            return null;
        }
        return obj.get(key);
    }

    /**
     * Get a string value by key (booleans/numbers are converted to strings).
     */
    public static String asString(Map<String, Object> obj, String key) {
        Object v = get(obj, key);
        if (v == null) {
            return "";
        }
        if (v instanceof Boolean) {
            return Boolean.toString((Boolean) v);
        }
        return String.valueOf(v);
    }

    /**
     * Get an array value by key as a {@code List<Object>}. Returns an empty
     * list when the key is absent or not an array.
     */
    public static List<Object> asList(Map<String, Object> obj, String key) {
        List<Object> out = new ArrayList<>();
        Object v = get(obj, key);
        if (v instanceof List) {
            out.addAll((List<Object>) v);
        }
        return out;
    }

    /**
     * Convert a JSON array into a list of parsed maps (used for channels and
     * messages which are delivered as arrays of objects).
     */
    public static List<Map<String, Object>> asObjectList(Map<String, Object> obj, String key) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : asList(obj, key)) {
            if (item instanceof Map) {
                out.add((Map<String, Object>) item);
            }
        }
        return out;
    }

    /**
     * Parser that implements just enough of RFC 8259 to handle API responses.
     */
    private static final class Parser {
        private final String src;
        private int pos;

        Parser(String src) {
            this.src = src;
        }

        private char peek() {
            if (pos >= src.length()) {
                return '\0';
            }
            return src.charAt(pos);
        }

        private char next() {
            if (pos >= src.length()) {
                throw new IllegalStateException("unexpected end of input");
            }
            return src.charAt(pos++);
        }

        private void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object parseValue() {
            skipWs();
            char c = peek();
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return parseNumberOrBare();
            }
        }

        private void expect(String word) {
            for (int i = 0; i < word.length(); i++) {
                if (next() != word.charAt(i)) {
                    throw new IllegalStateException("expected " + word);
                }
            }
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> result = new HashMap<>();
            next(); // '{'
            skipWs();
            if (peek() == '}') {
                next();
                return result;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                if (next() != ':') {
                    throw new IllegalStateException("expected ':'");
                }
                skipWs();
                Object value = parseValue();
                result.put(key, value);
                skipWs();
                char c = next();
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalStateException("expected ',' or '}'");
                }
            }
            return result;
        }

        private List<Object> parseArray() {
            List<Object> result = new ArrayList<>();
            next(); // '['
            skipWs();
            if (peek() == ']') {
                next();
                return result;
            }
            while (true) {
                skipWs();
                result.add(parseValue());
                skipWs();
                char c = next();
                if (c == ']') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalStateException("expected ',' or ']'");
                }
            }
            return result;
        }


        private String parseString() {
            if (next() != '"') {
                throw new IllegalStateException("expected '\"'");
            }
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    c = next();
                    switch (c) {
                        case '"':
                            sb.append('"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default:
                            sb.append(c);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Object parseNumberOrBare() {
            int start = pos;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t'
                        || c == '\n' || c == '\r') {
                    break;
                }
                pos++;
            }
            String token = src.substring(start, pos).trim();
            if (token.isEmpty()) {
                return "";
            }
            try {
                if (token.indexOf('.') >= 0 || token.indexOf('e') >= 0 || token.indexOf('E') >= 0) {
                    return Double.parseDouble(token);
                }
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                return token;
            }
        }
    }
}

