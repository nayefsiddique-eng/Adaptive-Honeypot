from backend.services import geoip_enricher


def test_default_lookup_does_not_send_ip_over_network(monkeypatch):
    monkeypatch.setattr(geoip_enricher.settings, "GEOIP_LOOKUP_BASE_URL", "")
    monkeypatch.setattr(geoip_enricher, "_geoip_cache", {})

    def reject_request(*args, **kwargs):
        raise AssertionError("Unconfigured GeoIP attempted network access")

    monkeypatch.setattr(geoip_enricher.httpx, "get", reject_request)
    assert geoip_enricher.enrich_ip("192.0.2.80")["source"] == "simulated"
    assert geoip_enricher.enrich_ip("8.8.8.8")["source"] == "simulated"
