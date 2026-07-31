# PHAL plugin - Network Manager

This plugin provides the network manager interface for OpenVoiceOS. It uses `nmcli` for all communication with NetworkManager. The D-Bus interface is a work in progress ([#15](https://github.com/OpenVoiceOS/ovos-PHAL-plugin-network-manager/pull/15)).

# Requires

This plugin needs `nmcli`.

# Install

```bash
pip install ovos-PHAL-plugin-network-manager
```

# Config

This plugin is an admin plugin. It needs to run as root and to be enabled in `mycroft.conf`.

```javascript
{
"PHAL": {
    "admin": {
        "ovos-PHAL-plugin-network-manager": {"enabled": true}
    }
}
}
```

If you omit this config, the plugin runs as the regular user. In that case, set the [polkit policy](https://github.com/OpenVoiceOS/ovos-buildroot/blob/5c7af8b05892206846ae06adb3478f1df620bf6b/buildroot-external/rootfs-overlay/base/etc/polkit-1/rules.d/50-org.freedesktop.NetworkManager.rules) to allow `nmcli` without sudo.

# Event Details

##### Scanning

This plugin scans for nearby networks. Use the following event to start a scan.

```python
# Scanning:
# ovos.phal.nm.scan
# - type: Request
# - description: Allows client to request for a network scan
#
# ovos.phal.nm.scan.complete
# - type: Response
# - description: Emited when the requested scan is completed
# with a network list
```

##### Connecting

This plugin connects to and disconnects from networks. Use the following events to manage a connection.

```python
# Connecting:
# ovos.phal.nm.connect
# - type: Request
# - description: Allows clients to connect to a given network
#
# ovos.phal.nm.connection.successful
# - type: Response
# - description: Emitted when a connection is successfully established
#
# ovos.phal.nm.connection.failure
# - type: Response
# - description: Emitted when a connection fails to establish
#
# Disconnecting:
# ovos.phal.nm.disconnect
# - type: Request
# - description: Allows clients to disconnect from a network
#
# ovos.phal.nm.disconnection.successful
# - type: Response
# - description: Emitted when a connection successfully disconnects
#
# ovos.phal.nm.disconnection.failure
# - type: Response
# - description: Emitted when a connection fails to disconnect
```

##### Forget Networks

This plugin also forgets networks that a client already connected to. Use the following events to forget a network.

```python
# Forgetting:
# ovos.phal.nm.forget
# - type: Request
# - description: Allows a client to forget a network
#
# ovos.phal.nm.forget.successful
# - type: Response
# - description: Emitted when a connection successfully is forgetten
#
# ovos.phal.nm.forget.failure
# - type: Response
# - description: Emitted when a connection fails to forget
```

# Related projects

- [OpenVoiceOS/ovos-PHAL](https://github.com/OpenVoiceOS/ovos-PHAL): the hardware abstraction layer this plugin extends
- [OpenVoiceOS/ovos-PHAL-plugin-wifi-setup](https://github.com/OpenVoiceOS/ovos-PHAL-plugin-wifi-setup): guides a device through first-time WiFi setup

# License

Apache-2.0
