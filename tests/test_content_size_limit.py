import asyncio

from backend.middleware import security


def test_body_limit_measures_stream_without_content_length(monkeypatch):
    monkeypatch.setattr(security.settings, "MAX_REQUEST_BODY_BYTES", 4)
    scope = {"type": "http", "method": "POST", "headers": []}

    async def exercise(chunks):
        messages = iter(chunks)
        sent = []
        received = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        async def app(_scope, receive, _send):
            received.append(await receive())

        await security.ContentSizeLimitMiddleware(app)(scope, receive, send)
        return sent, received

    def chunks(last_chunk):
        return [
            {"type": "http.request", "body": b"12", "more_body": True},
            {"type": "http.request", "body": last_chunk, "more_body": False},
        ]

    sent, received = asyncio.run(exercise(chunks(b"345")))
    assert sent[0]["status"] == 413
    assert received == []

    sent, received = asyncio.run(exercise(chunks(b"34")))
    assert sent == []
    assert received == [{"type": "http.request", "body": b"1234", "more_body": False}]
