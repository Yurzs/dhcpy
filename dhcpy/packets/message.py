import dataclasses
import functools
import ipaddress
import math
import string
import struct
import typing
import socket

from dhcpy.constants import BYTEORDER
from dhcpy.helpers import decode_ip4, encode_ip4, zfill_bytes
from dhcpy.packets.option import DHCPMessageType, MessageOption, EndOption


@dataclasses.dataclass
class Message:
    type: int
    hardware_address_type: int
    hardware_address_length: int
    hops: int
    transaction_id: int
    time_since_acquisition: int
    is_broadcast: int
    client_address: ipaddress.IPv4Address
    assigned_address: ipaddress.IPv4Address
    server_address: ipaddress.IPv4Address
    relay_address: ipaddress.IPv4Address
    client_hardware_address: string.hexdigits
    server_hostname: typing.Optional[str]
    boot_file_name: typing.Optional[str]
    options: typing.Optional[typing.List[MessageOption]]

    TYPE_REQUEST = 1
    TYPE_RESPONSE = 2

    HARDWARE_ADDRESS_ETHERNET = 1

    HARDWARE_ENCODE_MAP = {HARDWARE_ADDRESS_ETHERNET: bytearray.fromhex}

    @functools.cached_property
    def dhcp_type(self) -> typing.Optional[int]:
        for option in self.options:
            if isinstance(option, DHCPMessageType):
                return option.message_type

    @classmethod
    def decode(cls, data: bytearray):
        return cls(
            data[0],
            data[1],
            data[2],
            data[3],
            int.from_bytes(data[4:8], byteorder=BYTEORDER),
            int.from_bytes(data[8:10], byteorder=BYTEORDER),
            int.from_bytes(data[10:12], byteorder=BYTEORDER) >= 32768,
            decode_ip4(data[12:16]),
            decode_ip4(data[16:20]),
            decode_ip4(data[20:24]),
            decode_ip4(data[24:28]),
            data[28 : min(28 + data[2], 44)].hex().upper(),
            server_hostname=data[44:108].decode("utf-8").rstrip("\x00"),
            boot_file_name=data[108:236].decode("utf-8").rstrip("\x00"),
            options=MessageOption.parse(data[236:]),
        )

    def encode(self):
        encoded_message = bytearray()
        encoded_message += struct.pack(
            "!BBBBIHH",
            self.type,
            self.hardware_address_type,
            self.hardware_address_length,
            self.hops,
            self.transaction_id,
            self.time_since_acquisition,
            32768 if self.is_broadcast else 0,
        )

        for address in [
            self.client_address,
            self.assigned_address,
            self.server_address,
            self.relay_address,
        ]:
            encoded_message += encode_ip4(address)

        hardware_address_encode_method = self.HARDWARE_ENCODE_MAP[self.hardware_address_type]

        encoded_message += zfill_bytes(
            hardware_address_encode_method(self.client_hardware_address), 16
        )[:16]
        encoded_message += zfill_bytes(self.server_hostname.encode(), 64)[:64]
        encoded_message += zfill_bytes(self.boot_file_name.encode(), 128)[:128]

        if self.options:
            encoded_message += b"c\x82Sc"

        for option in self.options:
            encoded_message += option.encode()

        encoded_message += EndOption().encode()

        return zfill_bytes(encoded_message, 16 * math.ceil(len(encoded_message) / 16) + 12)

    def reply(
        self,
    ):

        Message(
            Message.TYPE_RESPONSE,
        )
