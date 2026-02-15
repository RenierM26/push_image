"""Diagnostics support for Push Image integration."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import PushImageConfigEntry
from .const import CONF_JSON_KEY, CONF_WEBHOOK_ID, DEFAULT_JSON_KEY


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: PushImageConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime_data = config_entry.runtime_data
    json_key = config_entry.data.get(CONF_JSON_KEY, DEFAULT_JSON_KEY)

    diagnostics: dict[str, Any] = {
        "webhook_id": config_entry.data.get(CONF_WEBHOOK_ID),
        "last_update": (
            runtime_data.last_updated.isoformat()
            if runtime_data.last_updated is not None
            else None
        ),
        "image_last_updated": (
            runtime_data.last_updated.isoformat()
            if runtime_data.last_updated is not None
            else None
        ),
        "last_image_size": runtime_data.last_image_size,
        "last_device_name": runtime_data.last_device_name,
    }

    if json_key:
        diagnostics["last_url"] = runtime_data.last_url

    return diagnostics
