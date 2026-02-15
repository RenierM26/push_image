"""Config flow for Push Image integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import webhook
from homeassistant.config_entries import ConfigEntry, ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    TextSelector,
    TextSelectorConfig,
)

from .const import (
    CONF_DEVICE_NAME_FILTER,
    CONF_DEVICE_NAME_KEY,
    CONF_JSON_KEY,
    CONF_NAME,
    CONF_SSL_VERIFY,
    CONF_TOKEN,
    CONF_WEBHOOK_ID,
    CONF_WEBHOOK_NOTIFIED,
    DEFAULT_DEVICE_NAME_FILTER,
    DEFAULT_DEVICE_NAME_KEY,
    DEFAULT_JSON_KEY,
    DEFAULT_SSL_VERIFY,
    DOMAIN,
)


class PushImageConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Push Image."""

    VERSION = 1

    @staticmethod
    def _normalize_filter_values(value: str) -> str:
        """Normalize comma-separated filter values and remove duplicates."""
        parts = [part.strip() for part in value.split(",")]
        normalized = [part for part in parts if part]
        return ", ".join(dict.fromkeys(normalized))

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> PushImageOptionsFlow:
        """Get options flow for this handler."""
        return PushImageOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            title = str(user_input[CONF_NAME]).strip()
            json_key = str(user_input[CONF_JSON_KEY]).strip()
            device_name_key = str(user_input.get(CONF_DEVICE_NAME_KEY, "")).strip()
            device_name_filter = str(
                user_input.get(CONF_DEVICE_NAME_FILTER, "")
            ).strip()
            device_name_filter = self._normalize_filter_values(device_name_filter)

            if not title:
                errors["base"] = "name_required"
            elif not json_key:
                errors["base"] = "json_key_required"
            elif device_name_filter and not device_name_key:
                errors["base"] = "device_name_key_required"
            else:
                user_input[CONF_JSON_KEY] = json_key
                user_input[CONF_DEVICE_NAME_KEY] = device_name_key
                user_input[CONF_DEVICE_NAME_FILTER] = device_name_filter
                token = user_input.get(CONF_TOKEN)
                if token is not None:
                    user_input[CONF_TOKEN] = str(token).strip()
                user_input[CONF_WEBHOOK_ID] = webhook.async_generate_id()
                user_input[CONF_WEBHOOK_NOTIFIED] = False
                return self.async_create_entry(title=title, data=user_input)

        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default="Last image"): TextSelector(
                    TextSelectorConfig()
                ),
                vol.Required(CONF_JSON_KEY, default=DEFAULT_JSON_KEY): TextSelector(
                    TextSelectorConfig()
                ),
                vol.Optional(
                    CONF_DEVICE_NAME_KEY, default=DEFAULT_DEVICE_NAME_KEY
                ): TextSelector(TextSelectorConfig()),
                vol.Optional(
                    CONF_DEVICE_NAME_FILTER, default=DEFAULT_DEVICE_NAME_FILTER
                ): TextSelector(TextSelectorConfig()),
                vol.Optional(
                    CONF_SSL_VERIFY, default=DEFAULT_SSL_VERIFY
                ): BooleanSelector(),
                vol.Optional(CONF_TOKEN, default=""): TextSelector(
                    TextSelectorConfig()
                ),
            }
        )

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)


class PushImageOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for Push Image."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    @staticmethod
    def _normalize_filter_values(value: str) -> str:
        """Normalize comma-separated filter values and remove duplicates."""
        parts = [part.strip() for part in value.split(",")]
        normalized = [part for part in parts if part]
        return ", ".join(dict.fromkeys(normalized))

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage integration options."""
        errors: dict[str, str] = {}

        if user_input is not None:
            title = str(user_input[CONF_NAME]).strip()
            json_key = str(user_input[CONF_JSON_KEY]).strip()
            device_name_key = str(user_input.get(CONF_DEVICE_NAME_KEY, "")).strip()
            device_name_filter = str(
                user_input.get(CONF_DEVICE_NAME_FILTER, "")
            ).strip()
            device_name_filter = self._normalize_filter_values(device_name_filter)

            if not title:
                errors["base"] = "name_required"
            elif not json_key:
                errors["base"] = "json_key_required"
            elif device_name_filter and not device_name_key:
                errors["base"] = "device_name_key_required"
            else:
                token = str(user_input.get(CONF_TOKEN, "")).strip()
                ssl_verify = bool(user_input.get(CONF_SSL_VERIFY, DEFAULT_SSL_VERIFY))
                self.hass.config_entries.async_update_entry(
                    self._config_entry,
                    title=title,
                )
                return self.async_create_entry(
                    title="",
                    data={
                        CONF_JSON_KEY: json_key,
                        CONF_DEVICE_NAME_KEY: device_name_key,
                        CONF_DEVICE_NAME_FILTER: device_name_filter,
                        CONF_SSL_VERIFY: ssl_verify,
                        CONF_TOKEN: token,
                    },
                )

        current = {**self._config_entry.data, **self._config_entry.options}
        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default=self._config_entry.title): TextSelector(
                    TextSelectorConfig()
                ),
                vol.Required(
                    CONF_JSON_KEY,
                    default=current.get(CONF_JSON_KEY, DEFAULT_JSON_KEY),
                ): TextSelector(TextSelectorConfig()),
                vol.Optional(
                    CONF_DEVICE_NAME_KEY,
                    default=current.get(CONF_DEVICE_NAME_KEY, DEFAULT_DEVICE_NAME_KEY),
                ): TextSelector(TextSelectorConfig()),
                vol.Optional(
                    CONF_DEVICE_NAME_FILTER,
                    default=current.get(
                        CONF_DEVICE_NAME_FILTER, DEFAULT_DEVICE_NAME_FILTER
                    ),
                ): TextSelector(TextSelectorConfig()),
                vol.Optional(
                    CONF_SSL_VERIFY,
                    default=bool(current.get(CONF_SSL_VERIFY, DEFAULT_SSL_VERIFY)),
                ): BooleanSelector(),
                vol.Optional(
                    CONF_TOKEN,
                    default=str(current.get(CONF_TOKEN, "")),
                ): TextSelector(TextSelectorConfig()),
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
