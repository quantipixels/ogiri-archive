// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;

class ModuleBoundariesTest {
    @Test
    void featureModulesHaveNoCyclesOrInternalLeaks() {
        ApplicationModules.of("com.quantipixels.ogiri").verify();
    }
}
