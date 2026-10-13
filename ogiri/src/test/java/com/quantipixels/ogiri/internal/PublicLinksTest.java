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

    @Test
    void emptyAllowlistAdmitsOnlyThePublicOrigin() {
        var links = new PublicLinks("https://Accounts.example.test:443/base", "/auth", List.of());
        assertTrue(links.allowed("https://accounts.example.test/reset?x=1"));
        assertTrue(links.allowed("https://ACCOUNTS.example.test:443/other"));
        assertFalse(links.allowed("https://evil.example/reset"));
        assertFalse(links.allowed("http://accounts.example.test/reset"));
        assertFalse(links.allowed("https://accounts.example.test:8443/reset"));
        assertFalse(links.allowed("https://app.accounts.example.test/reset"));
        assertFalse(links.allowed("https://evil.example@accounts.example.test/reset"));
    }
}
