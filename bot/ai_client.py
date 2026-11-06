from __future__ import annotations

import json
import logging
import time

import requests

from .keypool import KeyPool, parse_keys
from .utils import est_tokens

log = logging.getLogger("bot.ai")


class APIError(Exception):
    def __init__(self, status: int, message: str = ""):
        super().__init__(message or f"HTTP {status}")
        self.status = status
        self.message = message


class AIClient:
    """Minimal OpenAI-compatible chat client with streaming, retries and automatic API-key failover."""

    RETRY_STATUS = (500, 502, 503, 504)            # transient: retry the same key first
    KEY_STATUS = (401, 402, 403, 429)              # this key is the problem: go straight to the next one

    def __init__(self, base_url: str, api_key, model: str, timeout: int = 120, retries: int = 2, pool: int = 16,
                 strategy: str = "failover"):
        self.url = f"{base_url}/chat/completions"
        self.model = model
        self.timeout = timeout
        self.retries = retries
        self.pool = KeyPool(parse_keys(api_key), strategy)
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=pool)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({"Accept": "text/event-stream, application/json"})

    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self.session.close()

    def chat(self, messages, temperature=0.7, stream=True, on_delta=None):
        """Return (text, usage_dict). `on_delta(full_text)` is called while streaming.
        Every key is tried (healthy ones first) before the request is reported as failed."""
        body = {"model": self.model, "messages": messages, "temperature": temperature, "stream": stream}
        prompt_chars = sum(len(m["content"]) for m in messages)
        last = APIError(0, "no attempt")
        for key in self.pool.order():
            headers = {"Authorization": f"Bearer {key}"}
            for attempt in range(self.retries + 1):
                try:
                    resp = self.session.post(self.url, json=body, headers=headers, stream=stream,
                                             timeout=(10, self.timeout))
                except requests.RequestException as e:
                    last = APIError(0, str(e))
                    if attempt < self.retries:
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    self.pool.fail(key, 0)
                    break
                status = resp.status_code
                if status == 200:
                    try:
                        text, usage = self._read(resp, stream, on_delta)
                        if not text.strip():
                            raise APIError(0, "empty reply")
                    except APIError as e:               # broken stream / malformed body before any text
                        last = e
                        self.pool.fail(key, 0)
                        break
                    self.pool.ok(key)
                    if not usage:
                        usage = {"prompt_tokens": max(1, prompt_chars // 3), "completion_tokens": est_tokens(text)}
                    return text, usage
                last = APIError(status, self._error_text(resp))
                resp.close()
                if status in self.KEY_STATUS:
                    self.pool.fail(key, status)
                    break
                if status in self.RETRY_STATUS:
                    if attempt < self.retries:
                        time.sleep(1.0 * (attempt + 1))
                        continue
                    self.pool.fail(key, status)
                    break
                raise last                              # 400/404/...: the request itself is wrong, another key will not help
        raise last

    @staticmethod
    def _error_text(resp) -> str:
        try:
            j = resp.json()
            err = j.get("error", j)
            return err.get("message", str(err)) if isinstance(err, dict) else str(err)
        except ValueError:
            return resp.text[:200]

    @staticmethod
    def _read(resp, stream, on_delta):
        if not stream:
            try:
                data = resp.json()
                text = data["choices"][0]["message"]["content"] or ""
                return text, data.get("usage") or {}
            except (ValueError, KeyError, IndexError, TypeError) as e:
                raise APIError(0, f"malformed reply: {type(e).__name__}") from e
            finally:
                close = getattr(resp, "close", None)
                if close:
                    close()
        resp.encoding = "utf-8"
        text, usage = "", {}
        completed = False
        try:
            for raw in resp.iter_lines(chunk_size=1):
                if not raw:
                    continue
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    completed = True
                    break
                try:
                    obj = json.loads(payload)
                except ValueError:
                    continue
                if obj.get("usage"):
                    usage = obj["usage"]
                for ch in obj.get("choices") or []:
                    if ch.get("finish_reason") is not None:
                        completed = True
                    piece = (ch.get("delta") or {}).get("content")
                    if piece:
                        text += piece
                        if on_delta:
                            on_delta(text)
        except requests.RequestException as e:
            log.warning("stream interrupted: %s", e)
            raise APIError(0, f"stream interrupted: {type(e).__name__}") from e
        finally:
            resp.close()
        if not completed:
            raise APIError(0, "incomplete stream: missing terminal event")
        return text, usage
