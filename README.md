# Push Image

`push_image` creates an Image entity that updates when a webhook receives a
JSON payload containing an image URL.

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

If your `JSON key` is `event.image_url`:

```json
{
  "event": {
    "image_url": "https://nas.local:5001/webapi/entry.cgi?..."
  },
  "camera": "Front door",
  "time": "2026-02-14T08:00:00Z"
}
```

## Security token

- Leave `Token` empty to accept webhook calls without a token header.
- If `Token` is set, every webhook request must include:
  - `X-Push-Image-Token: <token>`
- Missing or incorrect token returns HTTP `401`.
