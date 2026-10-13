// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Public independent session operations; atomic workflow storage stays internal. */
public interface JdbcSessions {
    IssuedSession issue(Subject subject, String client);

    Optional<Session> authenticate(String token);

    List<Session> list(Subject subject);

    boolean revoke(Subject subject, UUID id);

    int revokeAll(Subject subject);

    int cleanup(int batchSize);
}
