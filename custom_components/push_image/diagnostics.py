"""Diagnostics support for Push Image integration."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import DEFAULT_ENTITY_KEY, PushImageConfigEntry
from .const import (
    CONF_DEVICE_NAME_FILTER,
    CONF_DEVICE_NAME_KEY,
    CONF_JSON_KEY,
    CONF_WEBHOOK_ID,
    DEFAULT_JSON_KEY,
)


def _entry_value(config_entry: PushImageConfigEntry, key: str, default: Any) -> Any:
    """Return a config value from options first, then data."""
    return config_entry.options.get(key, config_entry.data.get(key, default))


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: PushImageConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    del hass

    entities: dict[str, dict[str, Any]] = {}
    for entity_key, entity_data in config_entry.runtime_data.entities.items():
        entities[entity_key] = {
            "last_update": (
                entity_data.last_updated.isoformat()
                if entity_data.last_updated is not None
                else None
            ),
            "image_last_updated": (
                entity_data.last_updated.isoformat()
                if entity_data.last_updated is not None
                else None
            ),
            "last_image_size": entity_data.last_image_size,
            "last_device_name": entity_data.last_device_name,
            "last_url": entity_data.last_url,
            "last_raw_message": entity_data.last_raw_message,
        }

    # Keep compatibility fields for the default/single entity shape.
    default_data = entities.get(DEFAULT_ENTITY_KEY, {})

    return {
        "webhook_id": config_entry.data.get(CONF_WEBHOOK_ID),
        "json_key": _entry_value(config_entry, CONF_JSON_KEY, DEFAULT_JSON_KEY),
        "device_name_key": _entry_value(config_entry, CONF_DEVICE_NAME_KEY, ""),
        "device_name_filter": _entry_value(config_entry, CONF_DEVICE_NAME_FILTER, ""),
        "last_update": default_data.get("last_update"),
        "image_last_updated": default_data.get("image_last_updated"),
        "last_image_size": default_data.get("last_image_size"),
        "last_device_name": default_data.get("last_device_name"),
        "last_url": default_data.get("last_url"),
        "last_raw_message": config_entry.runtime_data.last_raw_message,
        "entities": entities,
    }
