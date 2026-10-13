# Recovery

If an administrator is locked out of mapped admin routes:

1. Stop claiming this plugin covers every admin API. Coverage is partial.
2. Edit the plugin configuration XML under the Jellyfin plugin configuration directory and set `RestrictAdminNetworks` to `false`.
3. Clear `AdminNetworks` if the list was wrong. An empty list disables the restriction even if the flag stays on.
4. Restart Jellyfin.
5. Playback is not governed by this restriction.

Do not change `jellyfin.db` to recover from a Jelly Security setting.

If the browser login asks for a challenge and the provider cannot be displayed:

1. TV and mobile apps are not challenged and can still sign in.
2. Edit the plugin configuration XML and set `CaptchaEnforceWeb` to `false`.
3. Restart Jellyfin. The checkbox is part of the plugin response, not a change to the Jellyfin web folder.
