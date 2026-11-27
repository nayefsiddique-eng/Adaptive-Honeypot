import asyncio
from types import SimpleNamespace
from starlette.responses import Response

from backend.middleware import security


def test_rate_limiter_prunes_idle_clients_and_skips_non_api(monkeypatch):
    clock = [1.0]
    monkeypatch.setattr(security, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(security.settings, "API_RATE_WINDOW_SECONDS", 10)
    monkeypatch.setattr(security.settings, "API_RATE_LIMIT", 1)
    middleware = security.InMemoryRateLimiterMiddleware(None)

    async def handle(request):
        return Response()

    def request(host, path="/api/status"):
        return SimpleNamespace(client=SimpleNamespace(host=host), url=SimpleNamespace(path=path))

    async def exercise_limiter():
        assert (await middleware.dispatch(request("first"), handle)).status_code == 200
        assert (await middleware.dispatch(request("first"), handle)).status_code == 429
        assert (await middleware.dispatch(request("ignored", "/"), handle)).status_code == 200
        assert "ignored" not in middleware.history

        clock[0] = 11.0
        assert (await middleware.dispatch(request("second"), handle)).status_code == 200
        assert set(middleware.history) == {"second"}

    asyncio.run(exercise_limiter())
