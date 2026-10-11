// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import java.util.Map;
import java.util.Optional;

/** Writes participate in the auth coordinator's transaction and use the same DataSource. */
public interface AccountStore {
    Optional<OgiriAccount> findByUid(String uid);

    Optional<OgiriAccount> findByEmail(String email);

    Optional<OgiriAccount> findById(String id);

    Optional<OgiriAccount> findByToken(String column, String digest);

    Optional<OgiriAccount> lock(String id);

    OgiriAccount create(Map<String, Object> columns);

    OgiriAccount update(String id, Map<String, Object> changes);

    void delete(String id);
}
