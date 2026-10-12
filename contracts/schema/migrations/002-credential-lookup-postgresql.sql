-- SPDX-License-Identifier: Apache-2.0
CREATE INDEX ogiri_sessions_credential_lookup ON ogiri_sessions (realm, client);
