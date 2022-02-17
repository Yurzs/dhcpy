from __future__ import annotations

import abc
import dataclasses
import functools
import ipaddress
import math
import struct
import typing
from dataclasses import field

from dhcpy.constants import BYTEORDER
from dhcpy.helpers import decode_ip4, encode_ip4

OPTIONS = {}


def add_type_and_len(f):
    @functools.wraps(f)
    def wrap(option, *args, **kwargs):
        result = f(option, *args, **kwargs)
        return bytearray(struct.pack("!BB", option.type, len(result))) + result

    return wrap


class MetaMessageOption(abc.ABCMeta):
    def __init__(cls, name, bases, namespace):
        super().__init__(name, bases, namespace)
        if "type" in namespace:
            OPTIONS[namespace["type"].default] = cls


@dataclasses.dataclass
class MessageOption(abc.ABC, metaclass=MetaMessageOption):
    type: int

    @classmethod
    def parse(cls, data: bytearray) -> typing.List[MessageOption]:
        options = []
        if data.startswith(b"c\x82Sc"):
            data = data[4:]
            while data:
                option_type = data[0]
                if option_type not in [PadOption.type, EndOption.type]:
                    option_length = data[1]
                    if option_type in OPTIONS:
                        data_chunk = data[2 : 2 + option_length]
                        option = OPTIONS[option_type].decode(data_chunk)
                        options.append(option)
                    else:
                        print(option_type)
                    data = data[2 + option_length :]
                    continue
                data = data[1:]
        return options

    @classmethod
    @abc.abstractmethod
    def decode(cls, data: bytearray):
        pass

    @abc.abstractmethod
    def encode(self):
        pass


@dataclasses.dataclass
class PadOption(MessageOption):
    type: int = field(default=0, init=False, repr=False)

    def encode(self) -> bytearray:
        return bytearray([self.type])

    @classmethod
    def decode(cls, data: bytearray):
        pass


@dataclasses.dataclass
class EndOption(MessageOption):
    type: int = field(default=255, init=False, repr=False)

    @classmethod
    def decode(cls, data: bytearray):
        pass

    def encode(self) -> bytearray:
        return bytearray([self.type])


@dataclasses.dataclass
class ServerMessageOption(MessageOption):
    servers: typing.List[ipaddress.IPv4Address]

    @classmethod
    def decode(cls, data: bytearray):
        servers = []
        while data:
            servers.append(decode_ip4(data[:4]))
            data = data[4:]
        return cls(servers)

    @add_type_and_len
    def encode(self) -> bytearray:
        encoded = bytearray()
        for server in self.servers:
            encoded += encode_ip4(server)
        return encoded


@dataclasses.dataclass
class SubnetMask(MessageOption):
    type: int = field(default=1, init=False, repr=False)

    mask: ipaddress.IPv4Address

    @classmethod
    def decode(cls, data: bytearray):
        return cls(decode_ip4(data))

    @add_type_and_len
    def encode(self) -> bytearray:
        return encode_ip4(self.mask)


@dataclasses.dataclass
class TimeOffset(MessageOption):
    type: int = field(default=2, init=False, repr=False)

    offset: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        encoded = bytearray()
        encoded += struct.pack("!I", self.offset)
        return encoded


@dataclasses.dataclass
class RouterOption(ServerMessageOption):
    type: int = field(default=3, init=False, repr=False)


@dataclasses.dataclass
class TimeServerOption(ServerMessageOption):
    type: int = field(default=4, init=False, repr=False)


@dataclasses.dataclass
class NameServerOption(ServerMessageOption):
    type: int = field(default=5, init=False, repr=False)


@dataclasses.dataclass
class DomainNameServerOption(ServerMessageOption):
    type: int = field(default=6, init=False, repr=False)


@dataclasses.dataclass
class LogServerOption(ServerMessageOption):
    type: int = field(default=7, init=False, repr=False)


@dataclasses.dataclass
class CookieServerOption(ServerMessageOption):
    type: int = field(default=8, init=False, repr=False)


@dataclasses.dataclass
class LPRServerOption(ServerMessageOption):
    type: int = field(default=9, init=False, repr=False)


@dataclasses.dataclass
class ImpressServerOption(ServerMessageOption):
    type: int = field(default=10, init=False, repr=False)


@dataclasses.dataclass
class ResourceLocationServerOption(ServerMessageOption):
    type: int = field(default=11, init=False, repr=False)


@dataclasses.dataclass
class HostNameOption(MessageOption):
    type: int = field(default=12, init=False, repr=False)

    hostname: str

    @classmethod
    def decode(cls, data: bytearray):
        return cls(hostname=data.decode())

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(self.hostname.encode())


@dataclasses.dataclass
class BootFileSizeOption(MessageOption):
    type: int = field(default=13, init=False, repr=False)

    file_size: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.file_size))


@dataclasses.dataclass
class RequestIPAddress(MessageOption):
    type: int = field(default=50, init=False, repr=False)

    address: ipaddress.IPv4Address

    @classmethod
    def decode(cls, data: bytearray):
        return cls(decode_ip4(data))

    @add_type_and_len
    def encode(self) -> bytearray:
        return encode_ip4(self.address)


@dataclasses.dataclass
class IPAddressLeaseTime(MessageOption):
    type: int = field(default=51, init=False, repr=False)

    time: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.time))


@dataclasses.dataclass
class DHCPMessageType(MessageOption):
    type: int = field(default=53, init=False, repr=False)

    message_type: int

    TYPE_DHCPDISCOVER = 1
    TYPE_DHCPOFFER = 2
    TYPE_DHCPREQUEST = 3
    TYPE_DHCPDECLINE = 4
    TYPE_DHCPACK = 5
    TYPE_DHCPNAK = 6
    TYPE_DHCPRELEASE = 7
    TYPE_DHCPINFORM = 8

    TYPES = [
        TYPE_DHCPDISCOVER,
        TYPE_DHCPOFFER,
        TYPE_DHCPREQUEST,
        TYPE_DHCPDECLINE,
        TYPE_DHCPACK,
        TYPE_DHCPNAK,
        TYPE_DHCPRELEASE,
        TYPE_DHCPINFORM,
    ]

    TYPE_NAME_MAP = {
        TYPE_DHCPDISCOVER: "DHCPDISCOVER",
        TYPE_DHCPOFFER: "DHCPOFFER",
        TYPE_DHCPREQUEST: "DHCPREQUEST",
        TYPE_DHCPDECLINE: "DHCPDECLINE",
        TYPE_DHCPACK: "DHCPACK",
        TYPE_DHCPNAK: "DHCPNAK",
        TYPE_DHCPRELEASE: "DHCPRELEASE",
        TYPE_DHCPINFORM: "DHCPINFORM",
    }

    @classmethod
    def decode(cls, data: bytearray):
        return cls(data[0])

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!B", self.message_type))

    def __repr__(self):
        return f"DHCPMessageType(message_type={self.TYPE_NAME_MAP[self.message_type]})"


@dataclasses.dataclass
class ParameterRequestList(MessageOption):
    type: int = field(default=55, init=False, repr=False)

    codes: typing.List[int]

    PARAMETER_SUBNET_MASK = 1
    PARAMETER_DNS_SERVERS = 3
    PARAMETER_STATIC_ROUTE = 33
    PARAMETER_ADDRESS_LEASE = 51
    PARAMETER_DHCP_MESSAGE_TYPE = 53
    PARAMETER_VENDOR_CLASS_IDENTIFIER = 60
    PARAMETER_TFTP_SERVER_NAME = 66
    PARAMETER_BOOT_FILE_NAME = 67
    PARAMETER_CLASSES_ROUTE = 121
    PARAMETER_TFTP_SERVER_ADDRESS = 150

    @classmethod
    def decode(cls, data: bytearray):
        return cls(list(data))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(self.codes)


@dataclasses.dataclass
class ErrorMessage(MessageOption):
    type: int = field(default=56, init=False, repr=False)

    message: str

    @classmethod
    def decode(cls, data: bytearray):
        return cls(data.decode())

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(self.message.encode())


@dataclasses.dataclass
class MaximumDHCPMessageSize(MessageOption):
    type: int = field(default=57, init=False, repr=False)

    max_size: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.max_size))


@dataclasses.dataclass
class Renewal(MessageOption):
    type: int = field(default=58, init=False, repr=False)

    interval: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.interval))


@dataclasses.dataclass
class Rebinding(MessageOption):
    type: int = field(default=59, init=False, repr=False)

    interval: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.interval))


@dataclasses.dataclass
class VendorClassIdentifier(MessageOption):
    type: int = field(default=60, init=False, repr=False)

    vendor: int

    @classmethod
    def decode(cls, data: bytearray):
        return cls(int.from_bytes(data, byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!I", self.vendor))


@dataclasses.dataclass
class ClientIdentifier(MessageOption):
    type: int = field(default=61, init=False, repr=False)

    client_type: int
    identifier: int

    @property
    def identifier_bytes_length(self):
        return math.ceil(self.identifier.bit_length() / 8)

    @classmethod
    def decode(cls, data: bytearray):
        return cls(data[0], int.from_bytes(data[1:], byteorder=BYTEORDER))

    @add_type_and_len
    def encode(self) -> bytearray:
        return bytearray(struct.pack("!B", self.client_type)) + self.identifier.to_bytes(
            self.identifier_bytes_length, byteorder=BYTEORDER
        )


@dataclasses.dataclass
class UserClassOption(MessageOption):
    type: int = field(default=77, init=False, repr=False)

    user_classes: typing.List[str]

    @classmethod
    def decode(cls, data: bytearray):
        user_classes = []
        while data:
            opt_len = data[0]
            user_classes.append(data[1 : 1 + opt_len].decode())
            data = data[1 + opt_len :]
        return cls(user_classes)

    @add_type_and_len
    def encode(self) -> bytearray:
        encoded = bytearray()
        for user_class in self.user_classes:
            data = user_class.encode()
            encoded += struct.pack("!B", len(data))
            encoded += data
        return encoded
