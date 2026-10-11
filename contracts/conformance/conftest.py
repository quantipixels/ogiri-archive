from collections.abc import Iterator
from typing import cast

import pytest

from profiles import PROFILES
from support import API, Database, Mailbox, Settings


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--base-url", required=True)
    parser.addoption("--database-url", required=True)
    parser.addoption("--mailpit-url", required=True)
    parser.addoption("--peer-url", default="")
    parser.addoption("--setting", action="append", default=[], help="OGIRI_NAME=value override")
    parser.addoption("--profile", choices=list(PROFILES), default="default")
    parser.addoption("--read-only", action="store_true")
    parser.addoption("--database-container", default="")
    parser.addoption("--reference", action="store_true", help="Pinned real DTA oracle")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        profiles = item.get_closest_marker("profiles")
        if profiles and config.getoption("profile") not in profiles.args:
            item.add_marker(
                pytest.mark.skip(reason="requires profile: " + ", ".join(profiles.args))
            )
        reference = item.get_closest_marker("reference_only")
        if reference and not config.getoption("reference"):
            item.add_marker(pytest.mark.skip(reason="DTA reference-only: " + reference.args[0]))
        only = item.get_closest_marker("ogiri_only")
        if only and config.getoption("reference"):
            item.add_marker(pytest.mark.skip(reason="Ogiri-only: " + only.args[0]))
        if item.get_closest_marker("ac2") and not config.getoption("peer_url"):
            item.add_marker(pytest.mark.skip(reason="AC2 requires --peer-url sharing this DB"))


@pytest.fixture(scope="session")
def settings(pytestconfig: pytest.Config) -> Settings:
    return Settings(
        str(pytestconfig.getoption("base_url")),
        str(pytestconfig.getoption("database_url")),
        str(pytestconfig.getoption("mailpit_url")),
        str(pytestconfig.getoption("profile")),
        bool(pytestconfig.getoption("reference")),
        str(pytestconfig.getoption("peer_url")),
        tuple(cast(list[str], pytestconfig.getoption("setting"))),
        str(pytestconfig.getoption("database_container")),
    )


@pytest.fixture
def api(settings: Settings) -> Iterator[API]:
    instance = API(settings.base_url)
    yield instance
    instance.close()


@pytest.fixture
def db(settings: Settings) -> Iterator[Database]:
    instance = Database(settings)
    yield instance
    instance.close()


@pytest.fixture
def mail(settings: Settings) -> Iterator[Mailbox]:
    instance = Mailbox(settings.mailpit_url)
    yield instance
    instance.close()


@pytest.fixture(autouse=True)
def fresh_fixture(request: pytest.FixtureRequest) -> None:
    if request.config.getoption("read_only"):
        # pytest leaves FixtureRequest.node unannotated; this fixture has function scope.
        item = cast(pytest.Item, request.node)  # pyright: ignore[reportUnknownMemberType]
        if item.name not in {
            "test_V2_invalid_validate",
            "test_S5_get_signin",
        }:
            pytest.fail("--read-only supports only anonymous V2 and GET S5 checks")
        return
    db = cast(Database, request.getfixturevalue("db"))
    mail = cast(Mailbox, request.getfixturevalue("mail"))
    db.reset()
    mail.clear()
