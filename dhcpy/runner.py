import asyncio

from dhcpy.constants import DHCP_IN_PORT
from dhcpy.protocol import DHCPServerInputProtocol

RUNNING = True


async def start_server():
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DHCPServerInputProtocol(), local_addr=("0.0.0.0", DHCP_IN_PORT)
    )

    while RUNNING:
        await asyncio.sleep(2)
    else:
        transport.close()


async def restart_server():
    global RUNNING

    RUNNING = False

    await asyncio.sleep(2)

    await start_server()


if __name__ == "__main__":
    asyncio.run(start_server())
