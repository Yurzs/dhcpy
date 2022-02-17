import asyncio

import dhcpy.constants
from dhcpy.packets.message import Message
from dhcpy.packets.option import DHCPMessageType


def proceed_message(message: Message):
    if message.type != Message.TYPE_REQUEST:
        return

    if message.dhcp_type == DHCPMessageType.TYPE_DHCPDISCOVER:
        print(message)
        print(f"OUT {len(message.encode())}")
        return message.encode()

    elif message.dhcp_type == DHCPMessageType.TYPE_DHCPREQUEST:
        pass
    elif message.dhcp_type == DHCPMessageType.TYPE_DHCPOFFER:
        pass
    elif message.dhcp_type == DHCPMessageType.TYPE_DHCPACK:
        pass
    elif message.dhcp_type == DHCPMessageType.TYPE_DHCPDECLINE:
        pass
