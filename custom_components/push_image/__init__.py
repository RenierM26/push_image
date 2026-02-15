"""Push Image integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
from homeassistant.util import dt as dt_util, slugify

from .const import (
    CONF_DEVICE_NAME_FILTER,
    CONF_DEVICE_NAME_KEY,
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
DEFAULT_ENTITY_KEY = "__default__"


@dataclass(slots=True)
class PushImageEntityData:
    """Per-entity runtime data for Push Image."""

    image_bytes: bytes | None = None
    content_type: str | None = None
    last_url: str | None = None
    last_update_monotonic: float = 0.0
    last_updated: datetime | None = None
    last_image_size: int | None = None
    last_device_name: str | None = None
    last_raw_message: dict[str, Any] | None = None


@dataclass(slots=True)
class PushImageRuntimeData:
    """Runtime data for Push Image."""

    entities: dict[str, PushImageEntityData] = field(default_factory=dict)
    configured_device_names: tuple[str, ...] = ()
    last_raw_message: dict[str, Any] | None = None


type PushImageConfigEntry = ConfigEntry[PushImageRuntimeData]


def _parse_device_name_filters(value: str) -> tuple[str, ...]:
    """Parse and normalize comma-separated device name filters."""
    parts = [part.strip() for part in value.split(",")]
    normalized = [part for part in parts if part]
    # Keep order stable and remove duplicates.
    return tuple(dict.fromkeys(normalized))


def _match_device_name_filter(
    configured_filters: tuple[str, ...], device_name: str
) -> str | None:
    """Return first configured filter that is contained in the device name."""
    for configured_filter in configured_filters:
        if configured_filter in device_name:
            return configured_filter
    return None


def _entry_value(entry: PushImageConfigEntry, key: str, default: Any) -> Any:
    """Return an entry value from options first, then data."""
    return entry.options.get(key, entry.data.get(key, default))


def _storage_path(hass: HomeAssistant, entry_id: str, entity_key: str) -> Path:
    """Return path for persisted image bytes."""
    base = Path(hass.config.path(".storage")) / STORAGE_DIRNAME
    if entity_key == DEFAULT_ENTITY_KEY:
        # Keep legacy filename for backward compatibility.
        return base / f"{entry_id}.bin"
    return base / f"{entry_id}_{slugify(entity_key)}.bin"


async def _load_last_bytes(
    hass: HomeAssistant, entry_id: str, entity_key: str
) -> bytes | None:
    """Load persisted image bytes for an entry entity."""
    path = _storage_path(hass, entry_id, entity_key)
    try:
        return await hass.async_add_executor_job(path.read_bytes)
    except FileNotFoundError:
        return None
    except OSError:
        _LOGGER.exception("Failed reading stored image for %s (%s)", entry_id, entity_key)
        return None


async def _load_last_updated_timestamp(
    hass: HomeAssistant, entry_id: str, entity_key: str
) -> datetime | None:
    """Load persisted image modification time as a UTC timestamp."""
    path = _storage_path(hass, entry_id, entity_key)
    try:
        stat_result = await hass.async_add_executor_job(path.stat)
    except FileNotFoundError:
        return None
    except OSError:
        _LOGGER.exception(
            "Failed reading stored image metadata for %s (%s)", entry_id, entity_key
        )
        return None

    return dt_util.utc_from_timestamp(stat_result.st_mtime)


async def _save_last_bytes(
    hass: HomeAssistant, entry_id: str, entity_key: str, data: bytes
) -> None:
    """Persist image bytes for an entry entity."""

    def _write_bytes(path: Path, content: bytes) -> None:
        """Write image bytes to disk with parent creation."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    path = _storage_path(hass, entry_id, entity_key)
    try:
        await hass.async_add_executor_job(_write_bytes, path, data)
    except OSError:
        _LOGGER.exception("Failed writing stored image for %s (%s)", entry_id, entity_key)


def _nested_value(payload: dict[str, Any], key_path: str) -> Any:
    """Safely return a possibly nested value using dot-separated keys."""
    current: Any = payload
    for key in key_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _show_webhook_notification(
    hass: HomeAssistant, entry: PushImageConfigEntry, webhook_id: str
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


async def async_setup_entry(hass: HomeAssistant, entry: PushImageConfigEntry) -> bool:
    """Set up Push Image from a config entry."""
    configured_device_names = _parse_device_name_filters(
        _entry_value(entry, CONF_DEVICE_NAME_FILTER, "")
    )
    if configured_device_names:
        runtime_entities = {
            device_name: PushImageEntityData(last_device_name=device_name)
            for device_name in configured_device_names
        }
    else:
        runtime_entities = {DEFAULT_ENTITY_KEY: PushImageEntityData()}

    entry.runtime_data = PushImageRuntimeData(
        entities=runtime_entities,
        configured_device_names=configured_device_names,
    )
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))

    # Restore bytes on startup (best-effort) per entity key.
    for entity_key, entity_data in entry.runtime_data.entities.items():
        restored = await _load_last_bytes(hass, entry.entry_id, entity_key)
        if restored is None:
            continue
        restored_ts = await _load_last_updated_timestamp(hass, entry.entry_id, entity_key)
        entity_data.image_bytes = restored
        # Content type for restored bytes is unknown; keep JPEG default fallback.
        entity_data.content_type = "image/jpeg"
        entity_data.last_image_size = len(restored)
        entity_data.last_updated = restored_ts
        async_dispatcher_send(hass, SIGNAL_UPDATED, entry.entry_id, entity_key)

    session = async_get_clientsession(hass)
    json_key: str = _entry_value(entry, CONF_JSON_KEY, DEFAULT_JSON_KEY)
    device_name_key: str = _entry_value(entry, CONF_DEVICE_NAME_KEY, "")
    ssl_verify: bool = bool(_entry_value(entry, CONF_SSL_VERIFY, False))
    token: str = _entry_value(entry, CONF_TOKEN, "")

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
        payload_dict: dict[str, Any] = payload
        runtime_data = entry.runtime_data
        runtime_data.last_raw_message = payload_dict

        url = _nested_value(payload_dict, json_key)
        if not url or not isinstance(url, str):
            return web.Response(
                text=f"Missing or invalid JSON key '{json_key}'", status=400
            )

        device_name: str | None = None
        if device_name_key:
            raw_device_name = _nested_value(payload_dict, device_name_key)
            if isinstance(raw_device_name, str):
                device_name = raw_device_name.strip()

        if runtime_data.configured_device_names:
            if device_name is None:
                _LOGGER.debug(
                    "Ignoring webhook for entry %s: device name missing",
                    entry.entry_id,
                )
                return web.Response(text="Ignored", status=200)
            matched_filter = _match_device_name_filter(
                runtime_data.configured_device_names, device_name
            )
            if matched_filter is None:
                _LOGGER.debug(
                    "Ignoring webhook for entry %s due to device filter mismatch",
                    entry.entry_id,
                )
                return web.Response(text="Ignored", status=200)
            entity_key = matched_filter
        else:
            entity_key = DEFAULT_ENTITY_KEY

        now = time.monotonic()
        entity_data = runtime_data.entities[entity_key]
        if now - entity_data.last_update_monotonic < DEBOUNCE_SECONDS:
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

        entity_data.image_bytes = img
        entity_data.content_type = content_type
        entity_data.last_url = url
        entity_data.last_update_monotonic = now
        entity_data.last_updated = dt_util.utcnow()
        entity_data.last_image_size = len(img)
        entity_data.last_device_name = device_name
        entity_data.last_raw_message = payload_dict

        _LOGGER.debug(
            "Fetched image for entry %s (content-type=%s size=%s bytes)",
            entry.entry_id,
            content_type,
            len(img),
        )

        # Persist bytes asynchronously; don't block webhook response too long
        hass.async_create_task(_save_last_bytes(hass, entry.entry_id, entity_key, img))

        async_dispatcher_send(hass, SIGNAL_UPDATED, entry.entry_id, entity_key)
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

    # Defensive unregister to avoid duplicate handler errors during reloads.
    webhook.async_unregister(hass, webhook_id)
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


async def async_unload_entry(hass: HomeAssistant, entry: PushImageConfigEntry) -> bool:
    """Unload a Push Image config entry."""
    webhook_id = entry.data.get(CONF_WEBHOOK_ID)
    if webhook_id:
        webhook.async_unregister(hass, webhook_id)
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)
