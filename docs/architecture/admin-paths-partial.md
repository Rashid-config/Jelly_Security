# Partial admin path map — Jellyfin 12.2

These write routes are classified as `Admin`. Everything else, including playback, is out of scope.

- POST `/Users` and `/Users/New`
- POST `/Users/{id}/Policy`
- DELETE `/Users/{id}`
- POST `/System/Configuration` and `/System/Configuration/Partial`

Startup routes are intentionally unclassified so a first-run wizard cannot be blocked by this partial map.

Not claimed: dashboard HTML, all plugin APIs except our own elevation policy, WebSocket admin, scheduled tasks, and any unlisted controller.

Session observation is limited to GET `/Sessions` and DELETE session routes. `/Sessions/*/Playing` stays unclassified.
