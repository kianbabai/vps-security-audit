"""Optional, local-only GeoIP enrichment."""

from __future__ import annotations

from pathlib import Path


def countries_for_ips(ips: list[str], database: str | None, errors: list[str]) -> dict[str, str]:
    if not database:
        return {}
    path = Path(database)
    if not path.is_file():
        errors.append(f"Configured GeoIP database does not exist: {path}")
        return {}
    try:
        import geoip2.database

        countries: dict[str, str] = {}
        with geoip2.database.Reader(str(path)) as reader:
            for ip in ips:
                try:
                    response = reader.country(ip)
                    countries[ip] = response.country.iso_code or response.country.name or "unknown"
                except Exception:
                    continue
        return countries
    except (ImportError, OSError) as exc:
        errors.append(f"GeoIP enrichment unavailable: {exc}")
        return {}

