"""Push Image integration."""

from __future__ import annotations

import functools
from json import JSONDecodeError
import logging
from pathlib import Path
import time
from typing import Any

from aiohttp import ClientError, ContentTypeError, web

from homeassistant.components import persistent_notification, webhook
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.util import dt as dt_util

from .const import (
    CONF_JSON_KEY,
    CONF_SSL_VERIFY,
    CONF_TOKEN,
    CONF_WEBHOOK_ID,
    CONF_WEBHOOK_NOTIFIED,
    DEBOUNCE_SECONDS,
    DEFAULT_JSON_KEY,
    DOMAIN,
    HEADER_PUSH_IMAGE_TOKEN,
    STORAGE_DIRNAME,
)

_LOGGER = logging.getLogger(__name__)

SIGNAL_UPDATED = f"{DOMAIN}_updated"

PLATFORMS: list[str] = ["image"]


def _storage_path(hass: HomeAssistant, entry_id: str) -> Path:
    """Return path for persisted image bytes."""
    # Use HA's config directory; store under .storage/push_image/<entry_id>.bin
    base = Path(hass.config.path(".storage")) / STORAGE_DIRNAME
    return base / f"{entry_id}.bin"


async def _load_last_bytes(hass: HomeAssistant, entry_id: str) -> bytes | None:
    """Load persisted image bytes for an entry."""
    path = _storage_path(hass, entry_id)
    try:
        return await hass.async_add_executor_job(path.read_bytes)
    except FileNotFoundError:
        return None
    except OSError:
        _LOGGER.exception("Failed reading stored image for %s", entry_id)
        return None


async def _save_last_bytes(hass: HomeAssistant, entry_id: str, data: bytes) -> None:
    """Persist image bytes for an entry."""
    path = _storage_path(hass, entry_id)
    try:
        await hass.async_add_executor_job(
            functools.partial(path.parent.mkdir, parents=True, exist_ok=True)
        )
        await hass.async_add_executor_job(path.write_bytes, data)
    except OSError:
        _LOGGER.exception("Failed writing stored image for %s", entry_id)


def _nested_value(payload: dict[str, Any], key_path: str) -> Any:
    """Safely return a possibly nested value using dot-separated keys."""
    current: Any = payload
    for key in key_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _show_webhook_notification(
    hass: HomeAssistant, entry: ConfigEntry, webhook_id: str
) -> None:
    """Show a persistent notification with webhook details."""
    webhook_path = f"/api/webhook/{webhook_id}"
    persistent_notification.async_create(
        hass,
        (
            "Use this webhook endpoint to push new images:\n\n"
            f"`{webhook_path}`\n\n"
            "If you configured a token, include this header:\n"
            f"`{HEADER_PUSH_IMAGE_TOKEN}: <token>`"
        ),
        title=f"Push Image webhook for {entry.title}",
        notification_id=f"{DOMAIN}_{entry.entry_id}_webhook",
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Push Image from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].setdefault(
        entry.entry_id,
        {
            "bytes": None,
            "content_type": None,
            "last_url": None,
            "last_update": 0.0,
            "last_update_ts": None,
            "last_image_size": None,
        },
    )

    # Restore bytes on startup (best-effort)
    restored = await _load_last_bytes(hass, entry.entry_id)
    if restored:
        hass.data[DOMAIN][entry.entry_id]["bytes"] = restored
        hass.data[DOMAIN][entry.entry_id]["content_type"] = (
            "image/jpeg"  # unknown; assume jpeg
        )
        hass.data[DOMAIN][entry.entry_id]["last_image_size"] = len(restored)
        async_dispatcher_send(hass, SIGNAL_UPDATED, entry.entry_id)

    session = async_get_clientsession(hass)
    json_key: str = entry.data.get(CONF_JSON_KEY, DEFAULT_JSON_KEY)
    ssl_verify: bool = bool(entry.data.get(CONF_SSL_VERIFY, False))
    token: str = entry.data.get(CONF_TOKEN, "")

    async def _handle_webhook(
        hass: HomeAssistant, webhook_id: str, request: web.Request
    ) -> web.Response:
        _LOGGER.debug("Webhook received for entry %s", entry.entry_id)

        if token:
            request_token = request.headers.get(HEADER_PUSH_IMAGE_TOKEN)
            if request_token != token:
                return web.Response(text="Unauthorized", status=401)

        try:
            payload = await request.json()
        except (ContentTypeError, JSONDecodeError):
            return web.Response(text="Invalid JSON", status=400)

        if not isinstance(payload, dict):
            return web.Response(text="JSON payload must be an object", status=400)

        url = _nested_value(payload, json_key)
        if not url or not isinstance(url, str):
            return web.Response(
                text=f"Missing or invalid JSON key '{json_key}'", status=400
            )

        now = time.monotonic()
        data = hass.data[DOMAIN][entry.entry_id]
        if now - data["last_update"] < DEBOUNCE_SECONDS:
            return web.Response(text="Ignored", status=200)

        try:
            # aiohttp uses ssl parameter: False disables verification
            ssl_param = ssl_verify
            async with session.get(url, ssl=ssl_param, allow_redirects=True) as resp:
                resp.raise_for_status()
                content_type = (
                    resp.headers.get("Content-Type", "image/jpeg").split(";")[0].strip()
                )
                img = await resp.read()
        except (ClientError, TimeoutError, ValueError) as err:
            _LOGGER.warning(
                "Failed to fetch image URL for entry %s: %s", entry.entry_id, err
            )
            return web.Response(text="Fetch failed", status=502)

        data["bytes"] = img
        data["content_type"] = content_type
        data["last_url"] = url
        data["last_update"] = now
        data["last_update_ts"] = dt_util.utcnow().isoformat()
        data["last_image_size"] = len(img)

        _LOGGER.debug(
            "Fetched image for entry %s (content-type=%s size=%s bytes)",
            entry.entry_id,
            content_type,
            len(img),
        )

        # Persist bytes asynchronously; don't block webhook response too long
        hass.async_create_task(_save_last_bytes(hass, entry.entry_id, img))

        async_dispatcher_send(hass, SIGNAL_UPDATED, entry.entry_id)
        return web.Response(text="OK")

    # One webhook per entry; HA creates a stable random webhook_id stored in entry
    entry_data = dict(entry.data)
    webhook_id = entry.data.get(CONF_WEBHOOK_ID)
    if webhook_id is None:
        # We must store a webhook_id; easiest is to create an updated entry with it.
        # But config entry data is immutable; use options or async_update_entry.
        webhook_id = webhook.async_generate_id()
        entry_data[CONF_WEBHOOK_ID] = webhook_id

    if not bool(entry.data.get(CONF_WEBHOOK_NOTIFIED, False)):
        _show_webhook_notification(hass, entry, webhook_id)
        entry_data[CONF_WEBHOOK_NOTIFIED] = True

    if entry_data != entry.data:
        hass.config_entries.async_update_entry(entry, data=entry_data)

    webhook.async_register(
        hass,
        DOMAIN,
        f"Push Image ({entry.title})",
        webhook_id,
        _handle_webhook,
        allowed_methods=["POST"],
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Push Image config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = hass.data.get(DOMAIN, {})
        data.pop(entry.entry_id, None)
        if not data:
            hass.data.pop(DOMAIN, None)
    return unload_ok
