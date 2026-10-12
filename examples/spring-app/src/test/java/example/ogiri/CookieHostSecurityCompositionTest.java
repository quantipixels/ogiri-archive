// SPDX-License-Identifier: Apache-2.0
package example.ogiri;

import org.springframework.test.context.TestPropertySource;

@TestPropertySource(properties = "ogiri.cookie-enabled=true")
class CookieHostSecurityCompositionTest extends HostSecurityCompositionTest {}
