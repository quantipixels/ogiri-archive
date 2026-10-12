// SPDX-License-Identifier: Apache-2.0
package com.quantipixels.ogiri.account;

import java.util.Map;
import java.util.Optional;

/** Writes participate in the auth coordinator's transaction and use the same DataSource. */
public interface AccountStore {
    /**
     * Email-provider shorthand. Token authentication resolves the stable session subject instead.
     */
    default Optional<OgiriAccount> findByUid(String uid) {
        return findByUid(uid, "email");
    }

    Optional<OgiriAccount> findByUid(String uid, String provider);

    Optional<OgiriAccount> findByEmail(String email);

    Optional<OgiriAccount> findById(String id);

    Optional<OgiriAccount> findByToken(String column, String digest);

    Optional<OgiriAccount> lock(String id);

    default OgiriAccount preview(Map<String, Object> columns) {
        return new OgiriAccount(columns, java.util.List.of());
    }

    OgiriAccount create(Map<String, Object> columns);

    OgiriAccount update(String id, Map<String, Object> changes);

    void delete(String id);
}
