"""Constants for the Push Image integration."""

DOMAIN = "push_image"

CONF_NAME = "name"
CONF_JSON_KEY = "json_key"
CONF_DEVICE_NAME_KEY = "device_name_key"
CONF_DEVICE_NAME_FILTER = "device_name_filter"
CONF_SSL_VERIFY = "ssl_verify"
CONF_TOKEN = "token"
CONF_WEBHOOK_ID = "webhook_id"
CONF_WEBHOOK_NOTIFIED = "webhook_notified"

DEFAULT_JSON_KEY = "image_url"
DEFAULT_DEVICE_NAME_KEY = ""
DEFAULT_DEVICE_NAME_FILTER = ""
DEFAULT_SSL_VERIFY = False
DEBOUNCE_SECONDS = 0.3
HEADER_PUSH_IMAGE_TOKEN = "X-Push-Image-Token"
STORAGE_DIRNAME = "push_image"
