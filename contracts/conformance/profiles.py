"""The single sample configuration interface; values are strings for process envs."""

BASE = {
    "OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST": "false",
    "OGIRI_MAX_NUMBER_OF_DEVICES": "10",
    "OGIRI_TOKEN_LIFESPAN_SECONDS": "1209600",
    "OGIRI_BATCH_REQUEST_BUFFER_THROTTLE_SECONDS": "5",
    "OGIRI_CONFIRMABLE": "false",
    "OGIRI_LOCKABLE": "false",
    "OGIRI_MAXIMUM_ATTEMPTS": "20",
    "OGIRI_UNLOCK_STRATEGY": "both",
    "OGIRI_UNLOCK_IN_SECONDS": "3600",
    "OGIRI_PARANOID": "false",
    "OGIRI_REDIRECT_ALLOWLIST": "https://client.example.test/*",
    "OGIRI_DEFAULT_CONFIRM_SUCCESS_URL": "",
    "OGIRI_DEFAULT_PASSWORD_RESET_URL": "",
    "OGIRI_REMOVE_TOKENS_AFTER_PASSWORD_RESET": "false",
    "OGIRI_REQUIRE_CLIENT_PASSWORD_RESET_TOKEN": "false",
    "OGIRI_CHECK_CURRENT_PASSWORD_BEFORE_UPDATE": "false",
    "OGIRI_COOKIE_ENABLED": "false",
    "OGIRI_RESET_PASSWORD_WITHIN_SECONDS": "21600",
}
PROFILES: dict[str, dict[str, str]] = {
    "default": {},
    "strict": {
        "OGIRI_CONFIRMABLE": "true",
        "OGIRI_LOCKABLE": "true",
        "OGIRI_MAXIMUM_ATTEMPTS": "3",
        "OGIRI_UNLOCK_IN_SECONDS": "30",
        "OGIRI_PARANOID": "true",
        "OGIRI_REDIRECT_ALLOWLIST": "https://*.example.test/*",
        "OGIRI_REMOVE_TOKENS_AFTER_PASSWORD_RESET": "true",
        "OGIRI_CHECK_CURRENT_PASSWORD_BEFORE_UPDATE": "attributes",
        "OGIRI_MAX_NUMBER_OF_DEVICES": "3",
    },
    "reset-token": {"OGIRI_REQUIRE_CLIENT_PASSWORD_RESET_TOKEN": "true"},
    "rotation": {"OGIRI_CHANGE_HEADERS_ON_EACH_REQUEST": "true"},
    "cookie": {"OGIRI_COOKIE_ENABLED": "true"},
}
REDIRECT = "https://client.example.test/done"


def environment(profile: str) -> dict[str, str]:
    return BASE | PROFILES[profile]
