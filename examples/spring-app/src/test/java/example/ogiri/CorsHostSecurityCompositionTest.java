// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

@TestPropertySource(properties = "host.cors=true")
class CorsHostSecurityCompositionTest extends HostSecurityCompositionTest {
    @Override
    @Test
    void hostCorsDisableSurvivesSourceBean() throws Exception {
        var response =
                request(
                        browser(),
                        "OPTIONS",
                        "/host/change",
                        "",
                        Map.of(
                                "Origin",
                                "https://client.example.test",
                                "Access-Control-Request-Method",
                                "POST"));
        assertEquals(200, response.statusCode());
        assertEquals(
                "https://client.example.test",
                response.headers().firstValue("Access-Control-Allow-Origin").orElseThrow());
    }
}
