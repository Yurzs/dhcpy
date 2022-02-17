import ipaddress
import struct
import typing


def decode_ip4(address_bytes: bytearray) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(".".join([str(i) for i in struct.unpack("!BBBB", address_bytes)]))


def encode_ip4(address: ipaddress.IPv4Address) -> bytearray:
    return bytearray([int(i) for i in str(address).split(".")])


def zfill_bytes(data: typing.Union[bytearray, bytes], length: int, filler=b"\x00"):
    return data + filler * max(0, (length - len(data)))
