"""Image platform for Push Image integration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.components.image import ImageEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SIGNAL_UPDATED, PushImageConfigEntry
from .const import CONF_WEBHOOK_ID


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PushImageConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Push Image image entity from a config entry."""
    async_add_entities([PushImageEntity(hass, entry)])


class PushImageEntity(ImageEntity):
    """Image entity that stores the most recently pushed image."""

    _attr_has_entity_name = True

    def __init__(self, hass: HomeAssistant, entry: PushImageConfigEntry) -> None:
        """Initialize the Push Image entity."""
        super().__init__(hass)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}"
        self._attr_name = entry.title
        self._unsub: Callable[[], None] | None = None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes for the entity."""
        runtime_data = self._entry.runtime_data
        webhook_id = self._entry.data.get(CONF_WEBHOOK_ID)
        return {
            "last_url": runtime_data.last_url,
            "last_device_name": runtime_data.last_device_name,
            "image_last_updated": (
                runtime_data.last_updated.isoformat()
                if runtime_data.last_updated is not None
                else None
            ),
            "webhook_id": webhook_id,
            "webhook_url": f"/api/webhook/{webhook_id}" if webhook_id else None,
        }

    def _update_last_updated_attr(self) -> None:
        """Update native image_last_updated from runtime data."""
        self._attr_image_last_updated = self._entry.runtime_data.last_updated

    async def async_added_to_hass(self) -> None:
        """Handle entity addition to Home Assistant."""
        self._update_last_updated_attr()

        @callback
        def _updated(entry_id: str) -> None:
            if entry_id == self._entry.entry_id:
                self._update_last_updated_attr()
                self.async_write_ha_state()

        self._unsub = async_dispatcher_connect(self.hass, SIGNAL_UPDATED, _updated)

    async def async_will_remove_from_hass(self) -> None:
        """Handle entity removal from Home Assistant."""
        if self._unsub:
            self._unsub()
            self._unsub = None

    async def async_image(self) -> bytes | None:
        """Return the currently stored image bytes."""
        runtime_data = self._entry.runtime_data
        # Update content type dynamically
        ct = runtime_data.content_type or "image/jpeg"
        self._attr_content_type = ct
        self._update_last_updated_attr()
        image_bytes = runtime_data.image_bytes
        return image_bytes if isinstance(image_bytes, bytes) else None
