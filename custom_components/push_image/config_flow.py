"""Config flow for Push Image integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import webhook
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers.selector import (
    BooleanSelector,
    TextSelector,
    TextSelectorConfig,
)

from .const import (
    CONF_JSON_KEY,
    CONF_NAME,
    CONF_SSL_VERIFY,
    CONF_TOKEN,
    CONF_WEBHOOK_ID,
    CONF_WEBHOOK_NOTIFIED,
    DEFAULT_JSON_KEY,
    DEFAULT_SSL_VERIFY,
    DOMAIN,
)


class PushImageConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Push Image."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            title = str(user_input[CONF_NAME]).strip()
            if not title:
                errors["base"] = "name_required"
            else:
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
                    CONF_SSL_VERIFY, default=DEFAULT_SSL_VERIFY
                ): BooleanSelector(),
                vol.Optional(CONF_TOKEN, default=""): TextSelector(
                    TextSelectorConfig()
                ),
            }
        )

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
