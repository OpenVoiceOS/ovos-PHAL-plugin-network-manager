import asyncio

from dbus_next.aio import MessageBus
from dbus_next.constants import BusType


class DbusNetworkManager:

    def get_access_points(self, wireless_device=None):
        if wireless_device:
            return asyncio.run(self._scan_wifi(wireless_device))
        return asyncio.run(self._scan_aps())

    def connect_to_ssid(self, ssid, passphrase):
        for dev in d.get_wireless_devices():
            asyncio.run(self._add_and_activate_ssid(ssid, dev, passphrase))
        return False

    def activate_ssid(self, ssid):
        # must have configured password previously
        ap = self.ssid2path(ssid)
        for dev in d.get_wireless_devices():
            asyncio.run(self._activate_con("/", dev, ap))
        return False

    def deactivate_ssid(self, ssid):
        asyncio.run(self._deactivate_ssid(ssid))
        return False

    def ssid2path(self, ssid):
        return asyncio.run(self._ssid2path(ssid))

    def enable_networking(self):
        return asyncio.run(self._enable_networking())

    def disable_networking(self):
        return asyncio.run(self._disable_networking())

    def get_devices(self):
        return asyncio.run(self._get_devices())

    def get_wireless_devices(self):
        return asyncio.run(self._find_wireless())

    def get_active_cons(self):
        return asyncio.run(self._get_active_cons())

    def activate_connection(self, con_path, dev_path, obj_path):
        return asyncio.run(self._activate_con(con_path, dev_path, obj_path))

    def deactivate_connection(self, con_path):
        return asyncio.run(self._deactivate_con(con_path))

    async def _get_nm_iface(self, dbus_bus):
        introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        obj = dbus_bus.get_proxy_object("org.freedesktop.NetworkManager",
                                        "/org/freedesktop/NetworkManager",
                                        introspection)
        return obj.get_interface("org.freedesktop.NetworkManager")

    async def _get_ap_info(self, dbus_bus, access_point):
        access_point_introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager', access_point)
        access_point_proxy = dbus_bus.get_proxy_object(
            "org.freedesktop.NetworkManager", access_point, access_point_introspection)
        access_point_interface = access_point_proxy.get_interface(
            "org.freedesktop.NetworkManager.AccessPoint")

        return {
            "access_point_flags": await access_point_interface.get_flags(),
            "access_point_wpa_flags": await access_point_interface.get_wpa_flags(),
            "access_point_rsn_flags": await access_point_interface.get_rsn_flags(),
            "access_point_ssid": await access_point_interface.get_ssid(),
            "access_point_signal_strength": await access_point_interface.get_strength(),
            "access_point_connection_path": access_point_interface.path,
            "access_point_mode": await access_point_interface.get_mode(),
            "access_point_hw_address": await access_point_interface.get_hw_address()
        }

    async def _connect(self):
        return await MessageBus(bus_type=BusType.SYSTEM).connect()

    async def _get_devices(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.call_get_devices()

    async def _get_device_type(self, dbus_bus, device):
        introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        device_obj = dbus_bus.get_proxy_object("org.freedesktop.NetworkManager", device, introspection)
        device_props = device_obj.get_interface("org.freedesktop.DBus.Properties")
        device_type = await device_props.call_get("org.freedesktop.NetworkManager.Device", "DeviceType")
        return device_type

    async def _find_wireless(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        wifi_device_introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager',
                                                              '/org/freedesktop/NetworkManager/Devices')
        wifi_device_obj = dbus_bus.get_proxy_object("org.freedesktop.NetworkManager",
                                                    "/org/freedesktop/NetworkManager/Devices",
                                                    wifi_device_introspection)
        wifi_devs = []
        for local_path in [child_path for child_path in wifi_device_obj.child_paths]:
            try:
                local_path_introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager',
                                                                     local_path)
                local_path_object = dbus_bus.get_proxy_object(
                    "org.freedesktop.NetworkManager", local_path, local_path_introspection)
                if local_path_object.get_interface("org.freedesktop.NetworkManager.Device.Wireless"):
                    wifi_devs.append(local_path)  # found wireless device
            except:
                continue
        return wifi_devs

    async def _scan_wifi(self, wireless_object_path, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        wireless_object_introspection = await dbus_bus.introspect('org.freedesktop.NetworkManager',
                                                                  wireless_object_path)
        wireless_object_proxy = dbus_bus.get_proxy_object(
            "org.freedesktop.NetworkManager", wireless_object_path, wireless_object_introspection)
        wireless_object_interface = wireless_object_proxy.get_interface(
            "org.freedesktop.NetworkManager.Device.Wireless")
        await wireless_object_interface.call_request_scan({})
        access_points = await wireless_object_interface.call_get_access_points()
        return [await self._get_ap_info(dbus_bus, ap)
                for ap in access_points]

    async def _scan_aps(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()

        # ensure networking is enabled before the scan
        try:
            await self._enable_networking(dbus_bus)
        except:
            pass  # already enabled TODO check state before enabling

        wif = await self._find_wireless(dbus_bus)
        if len(wif) == 0:
            return []
        # select first wireless device (usually wlan0)
        wifi_dev = wif[0]
        return await self._scan_wifi(wifi_dev, dbus_bus)

    async def _enable_networking(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.call_enable(True)

    async def _disable_networking(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.call_enable(False)

    async def _get_active_cons(self, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.get_active_connections()

    async def _activate_con(self, con_path, dev_path, obj_path, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.call_activate_connection(con_path, dev_path, obj_path)

    async def _add_and_activate_ssid(self, ssid, dev_path, passphrase, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()

        ap_path = await self._ssid2path(ssid, dbus_bus)

        iface = await self._get_nm_iface(dbus_bus)

        if passphrase is None:
            pass  # TODO - open network

        # what's the correct way to pass this ?
        connection_params = {
            "802-11-wireless": {
                "security": "802-11-wireless-security",
            },
            "802-11-wireless-security": {
                "key-mgmt": "wpa-psk",
                "psk": passphrase
            },
        }
        # TODO - dbus_next.errors.SignatureBodyMismatchError: DBus VARIANT type "v" must be Python type "Variant", got <class 'str'>
        return await iface.call_add_and_activate_connection(connection_params,
                                                            dev_path,
                                                            ap_path)

    async def _deactivate_con(self, con_path, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        iface = await self._get_nm_iface(dbus_bus)
        return await iface.call_deactivate_connection(con_path)

    async def _deactivate_ssid(self, ssid, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()

        con = await self._ssid2path(ssid, dbus_bus)
        # TODO - how to go from '/org/freedesktop/NetworkManager/AccessPoint/13333'
        #  to '/org/freedesktop/NetworkManager/ActiveConnection/1'
        await self._deactivate_con(con, dbus_bus)

    async def _ssid2path(self, ssid, dbus_bus=None):
        if not dbus_bus:
            dbus_bus = await self._connect()
        for ap in await self._scan_aps(dbus_bus):
            if ap['access_point_ssid'].decode("utf-8") == ssid:
                return ap['access_point_connection_path']


if __name__ == "__main__":
    d = DbusNetworkManager()
    dev = "/org/freedesktop/NetworkManager/Devices/3"
    ap1 = '/org/freedesktop/NetworkManager/AccessPoint/13376'
    ap2 = '/org/freedesktop/NetworkManager/AccessPoint/13333'

    # print(d.ssid2path('NOS-9207-5'))
    # TODO - cant get this one to work...
    d.connect_to_ssid('NOS-9207', "PSWD_HERE")
    # d.activate_ssid('NOS-9207')
    exit()
    for dev in d.get_wireless_devices():
        print(dev)

    for dev in d.get_devices():
        print(dev)

    for con in d.get_active_cons():
        print(con)
    # d.deactivate_connection("/org/freedesktop/NetworkManager/ActiveConnection/4")

    for ap in d.get_access_points():
        print(ap)

    # specific device also works
    print(d.get_access_points("/org/freedesktop/NetworkManager/Devices/3"))
