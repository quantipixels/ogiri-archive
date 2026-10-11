"""Foreground sample launcher, owned and stopped by the conformance runner."""
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

url = os.environ.get("OGIRI_DATABASE_URL", "")
if url and not url.startswith("jdbc:"):
    parts = urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql", "mysql"):
        raise ValueError("Unsupported sample database scheme")
    scheme = "postgresql" if parts.scheme == "postgres" else parts.scheme
    host = parts.hostname
    if host is None:
        raise ValueError("Sample database URL needs a hostname")
    if ":" in host:
        host = "[" + host + "]"
    authority = host + (":" + str(parts.port) if parts.port else "")
    os.environ["OGIRI_DATABASE_URL"] = "jdbc:" + scheme + "://" + authority + parts.path + ("?" + parts.query if parts.query else "")
    os.environ["OGIRI_JDBC_USER"] = unquote(parts.username or "")
    os.environ["OGIRI_JDBC_PASSWORD"] = unquote(parts.password or "")
jar = Path(__file__).resolve().parent / "target" / "spring-app-0.0.1.jar"
os.execvp("java", ["java", "-jar", str(jar)])
