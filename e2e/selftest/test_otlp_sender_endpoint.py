"""NAN-5878: the OTLP sender reaches the edge as the `edge` service on the
stack's compose network. On Linux the edge publishes on host 127.0.0.1 only,
so `host.docker.internal` (host-gateway, 172.17.0.1) was refused there."""

from __future__ import annotations

from nano_e2e.otlp import _container_ingest_endpoint


def test_the_edge_is_reached_on_the_compose_network() -> None:
    edge = "http://127.0.0.1:35591"
    assert _container_ingest_endpoint(edge, edge) == "http://edge:80/otlp"
    assert _container_ingest_endpoint("http://localhost:35591/", edge) == "http://edge:80/otlp"


def test_other_loopback_urls_still_use_the_host_gateway() -> None:
    assert (
        _container_ingest_endpoint("http://127.0.0.1:4000", "http://127.0.0.1:35591")
        == "http://host.docker.internal:4000/otlp"
    )
    assert _container_ingest_endpoint("http://127.0.0.1:4000") == "http://host.docker.internal:4000/otlp"


def test_a_remote_ingest_url_is_untouched() -> None:
    assert (
        _container_ingest_endpoint("https://ingest.example.test", "http://127.0.0.1:35591")
        == "https://ingest.example.test/otlp"
    )
