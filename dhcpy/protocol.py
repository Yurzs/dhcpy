import asyncio
import ipaddress
import typing

from dhcpy.dispatcher import proceed_message
from dhcpy.packets.message import Message


class DHCPServerInputProtocol(asyncio.DatagramProtocol):
    transport: asyncio.transports.DatagramTransport

    def connection_made(self, transport: asyncio.transports.DatagramTransport) -> None:
        self.transport = transport
        print("Connection made")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        print(self.transport.get_extra_info("pipe"))
        message = Message.decode(bytearray(data))
        proceed_message(message)


class DCHPServerOutputProtocol(asyncio.BaseProtocol):
    def __init__(self, message: Message, on_connection_lost):
        self.message = message
        self.on_connection_lost = on_connection_lost
        self.transport: None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.transport.sendto(self.message.encode())

    def datagram_received(self, data, address):
        message = Message.decode(bytearray(data))
        print(message)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass

    @classmethod
    async def send_message(
        cls, message: Message, host: typing.Union[str, ipaddress.IPv4Address], port: int
    ):
        loop = asyncio.get_running_loop()

        on_connection_lost = asyncio.Future()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: cls(message, on_connection_lost), remote_addr=(host, port)
        )

        try:
            await on_connection_lost
        finally:
            transport.close()
