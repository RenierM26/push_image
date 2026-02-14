"""Diagnostics support for Push Image integration."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_JSON_KEY, CONF_WEBHOOK_ID, DEFAULT_JSON_KEY, DOMAIN


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    data: dict[str, Any] = hass.data.get(DOMAIN, {}).get(config_entry.entry_id, {})
    json_key = config_entry.data.get(CONF_JSON_KEY, DEFAULT_JSON_KEY)

    diagnostics: dict[str, Any] = {
        "webhook_id": config_entry.data.get(CONF_WEBHOOK_ID),
        "last_update": data.get("last_update_ts"),
        "last_image_size": data.get("last_image_size"),
    }

    if json_key:
        diagnostics["last_url"] = data.get("last_url")

    return diagnostics
