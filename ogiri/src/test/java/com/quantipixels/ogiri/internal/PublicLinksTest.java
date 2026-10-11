// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PublicLinksTest {
    @Test
    void hostGlobsCannotMatchQueryFragmentOrUserinfo() {
        var links =
                new PublicLinks(
                        "https://accounts.example.test",
                        "/app/api/login",
                        List.of("https://*.example.com/*"));
        assertTrue(links.allowed("https://client.example.com/reset?x=1#done"));
        assertFalse(links.allowed("https://evil.test/#.example.com/x"));
        assertFalse(links.allowed("https://evil.test/?a=.example.com/"));
        assertFalse(links.allowed("https://evil.test@client.example.com/reset"));
        assertFalse(links.allowed("https://client.example.com:444/reset"));
        assertFalse(links.allowed("http://client.example.com/reset"));
        assertTrue(
                new PublicLinks(
                                "https://accounts.example.test",
                                "/auth",
                                List.of("https://client.example.com:*/reset*"))
                        .allowed("https://client.example.com:444/reset?a=1"));
        assertEquals(
                "https://accounts.example.test/app/api/login/password/edit?token=abc",
                links.mail("/password/edit", Map.of("token", "abc")));
    }
}
