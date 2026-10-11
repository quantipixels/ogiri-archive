// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.quantipixels.ogiri.account.OgiriSettings;
import com.quantipixels.ogiri.security.DtaAuthenticationToken;
import com.quantipixels.ogiri.security.internal.DtaAuthenticationConverter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class DtaCredentialTest {
    @Test
    void namedFieldsOverrideFallbackIndividuallyAndQueryParametersAreIgnored() {
        var converter = new DtaAuthenticationConverter(OgiriSettings.defaults());
        var request = new MockHttpServletRequest();
        request.addHeader(
                "Authorization",
                "Bearer "
                        + Base64.getEncoder()
                                .encodeToString(
                                        "{\"uid\":\"a@example.com\",\"client\":\"browser\",\"access-token\":\"fallback\"}"
                                                .getBytes(StandardCharsets.UTF_8)));
        request.addHeader("access-token", "header");
        var credential = ((DtaAuthenticationToken) converter.convert(request)).getCredentials();
        assertEquals("header", credential.token());
        assertEquals("browser", credential.client());
        assertEquals("a@example.com", credential.uid());
        var query = new MockHttpServletRequest();
        query.addParameter("uid", "a@example.com");
        query.addParameter("access-token", "ignored");
        assertNull(converter.convert(query));
        for (String value :
                new String[] {
                    "Bearer null",
                    "Bearer !!!",
                    "Bearer "
                            + Base64.getEncoder()
                                    .encodeToString("null".getBytes(StandardCharsets.UTF_8))
                }) {
            var malformed = new MockHttpServletRequest();
            malformed.addHeader("Authorization", value);
            assertNull(converter.convert(malformed));
        }
        var missingClient = new MockHttpServletRequest();
        missingClient.addHeader("uid", "a@example.com");
        missingClient.addHeader("access-token", "token");
        assertEquals(
                "default",
                ((DtaAuthenticationToken) converter.convert(missingClient))
                        .getCredentials()
                        .client());
    }
}
