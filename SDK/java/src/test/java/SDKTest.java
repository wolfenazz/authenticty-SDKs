import com.authenticity.Authenticity;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SDKTest {

    static final List<String> calls = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            calls.add(method + " " + path + " " + body);

            String reply;
            if (path.endsWith("/auth/login") || path.endsWith("/auth/login-user")) {
                reply = "{\"success\":\"true\",\"token\":\"TOK\",\"expiry\":\"2030-01-01T00:00:00Z\","
                        + "\"username\":\"demo\",\"ip\":\"1.2.3.4\",\"appName\":\"MyApp\","
                        + "\"appVersion\":\"1.0.0\",\"appStatus\":\"active\",\"level\":2,\"hwidLock\":\"false\"}";
            } else if (path.endsWith("/auth/register")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/auth/check")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/auth/check-blacklist")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/auth/ban")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/vars/get")) {
                reply = "{\"success\":\"true\",\"value\":\"hello-world\"}";
            } else if (path.endsWith("/files/download")) {
                reply = "{\"success\":\"true\",\"url\":\"http://127.0.0.1:" + server.getAddress().getPort()
                        + "/file.bin\"}";
            } else if (path.endsWith("/webhooks/trigger")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/logs/add")) {
                reply = "{\"success\":\"true\"}";
            } else if (path.endsWith("/chat/channels")) {
                reply = "{\"success\":\"true\",\"channels\":[{\"id\":\"c1\",\"name\":\"General\"}]}";
            } else if (path.endsWith("/chat/messages") && method.equals("POST")) {
                reply = "{\"success\":\"true\",\"messages\":[{\"id\":\"m1\",\"channelId\":\"c1\",\"senderId\":\"user-1\",\"sender\":\"أهلا\",\"avatarId\":\"AVATAR_2\",\"content\":\"hi\"}]}";
            } else if (path.endsWith("/chat/messages") && method.equals("PUT")) {
                reply = "{\"success\":\"true\",\"message\":\"Message sent\"}";
            } else if (path.endsWith("/chat/profile")) {
                reply = "{\"success\":\"true\",\"profileId\":\"user-1\",\"nickname\":\"أهلا\",\"avatarId\":\"AVATAR_2\"}";
            } else if (path.equals("/file.bin")) {
                byte[] data = "BYTES".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                }
                return;
            } else {
                reply = "{\"success\":\"true\"}";
            }
            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();

        runCalls(server);
        server.stop(0);
    }

    static void runCalls(HttpServer server) throws Exception {
        String api = "http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1/client";
        Authenticity c = new Authenticity("OID", "AID", api, "1.0.0", "KEY");

        assertTrue(c.login(), "login");
        assertTrue(c.loginWithCredentials("u", "p"), "loginWithCredentials");
        assertTrue(c.register("n", "pw", "K"), "register");
        assertTrue(c.checkSession(), "checkSession");
        assertFalse(c.checkBlacklist(), "checkBlacklist"); // returns true only when blacklisted
        assertEquals("hello-world", c.getVariable("welcomeMessage"), "getVariable");
        assertTrue(c.triggerWebhook("w", "data"), "triggerWebhook");
        c.log("app started", "info");

        // Chat before ban (ban invalidates the session)
        assertEquals(1, c.getChannels().size(), "getChannels size");
        assertEquals("c1", c.getChannels().get(0).get("id"), "getChannels id");
        assertEquals(1, c.getMessages("c1").size(), "getMessages size");
        assertEquals("user-1", c.getMessages("c1").get(0).get("senderId"), "message sender ID");
        assertEquals("user-1", c.getChatProfile().get("id"), "getChatProfile");
        assertEquals("أهلا", c.updateChatProfile("أهلا", "AVATAR_2").get("nickname"), "updateChatProfile");
        assertTrue(c.sendMessage("c1", "hey"), "sendMessage");

        byte[] file = c.downloadFile("f1");
        assertEquals("BYTES", new String(file, StandardCharsets.UTF_8), "downloadFile bytes");
        // End-to-end check: persist to disk and verify byte count.
        java.nio.file.Path out = java.nio.file.Paths.get("downloaded_f1.bin");
        java.nio.file.Files.write(out, file);
        assertEquals((long) file.length, java.nio.file.Files.size(out), "downloadFile saved size");
        java.nio.file.Files.deleteIfExists(out);

        assertTrue(c.ban("tamper"), "ban");

        System.out.println("NUM CALLS: " + calls.size());
        for (String call : calls) {
            System.out.println(call);
        }
        String loginBody = calls.stream().filter(x -> x.contains("/auth/login ")).findFirst().orElse("");
        assertTrue(loginBody.contains("\"ownerId\"") && loginBody.contains("\"licenseKey\"")
                && loginBody.contains("\"hwid\"") && loginBody.contains("\"version\""), "login body keys");
        String sendBody = calls.stream().filter(x -> x.startsWith("PUT ") && x.contains("/chat/messages"))
                .findFirst().orElse("");
        assertTrue(sendBody.contains("\"channelId\"") && sendBody.contains("\"content\""), "send body keys");
        String profileBody = calls.stream().filter(x -> x.startsWith("PUT ") && x.contains("/chat/profile"))
                .findFirst().orElse("");
        assertTrue(profileBody.contains("\"nickname\"") && profileBody.contains("\"avatarId\"")
                && profileBody.contains("أهلا"), "profile body and Unicode nickname");
        System.out.println("ALL JAVA MOCK TESTS PASSED");
    }

    static void assertTrue(boolean v, String name) {
        if (!v) throw new AssertionError("FAILED: " + name);
        System.out.println("PASS: " + name);
    }

    static void assertFalse(boolean v, String name) {
        if (v) throw new AssertionError("FAILED: " + name);
        System.out.println("PASS: " + name);
    }

    static void assertEquals(Object expected, Object actual, String name) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("FAILED: " + name + " expected=" + expected + " actual=" + actual);
        }
        System.out.println("PASS: " + name);
    }
}
