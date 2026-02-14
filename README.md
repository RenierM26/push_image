# Push Image

`push_image` creates an Image entity that updates when a webhook receives a
JSON payload containing an image URL.

## Install with HACS

1. Open HACS in Home Assistant.
2. Go to `Integrations`.
3. Open the menu (top-right) and select `Custom repositories`.
4. Add this repository URL and choose category `Integration`.
5. Find `Push Image` in HACS and select `Download`.
6. Restart Home Assistant.
7. Add the integration from `Settings` → `Devices & services` → `Add integration`.

## Setup

1. Add the integration from the UI.
2. Enter:
   - `Name`: entity display name.
   - `JSON key`: key path to the image URL (supports nested paths like
     `event.image_url`).
   - `Verify SSL`: enable certificate validation when fetching the URL.
   - `Token` (optional): if set, webhook requests must include
     `X-Push-Image-Token`.
3. Save.
4. Open the entity attributes to get:
   - `webhook_id`
   - `webhook_url` (for example `/api/webhook/<webhook_id>`)
   - `image_last_updated`
5. Check notifications in Home Assistant:
   - On first setup, the integration creates a persistent notification with the
     webhook path you can copy.

## Example curl

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Push-Image-Token: your_token_here" \
  -d '{"image_url":"https://example.com/camera.jpg"}' \
  "http://homeassistant.local:8123/api/webhook/<webhook_id>"
```

## Example Synology payload

Use this with `JSON key` set to `image_url`:

```json
{
  "image_url": "https://nas.local:5001/webapi/SurveillanceStation/Webhook/GetThumbnail/v1/example-0/THUMBNAIL_URL.jpg?v=11880",
  "camera": "Camera01",
  "time": "2023-02-01T15:05:39"
}
```

Only the configured `JSON key` value is used for image fetching. Other fields
such as `camera` and `time` are accepted but ignored by the integration.

## Security token

- Leave `Token` empty to accept webhook calls without a token header.
- If `Token` is set, every webhook request must include:
  - `X-Push-Image-Token: <token>`
- Missing or incorrect token returns HTTP `401`.
