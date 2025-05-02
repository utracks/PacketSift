# PacketSift

**Custom Packet Sniffer and Filter**

## Description:
PacketSift is a customizable packet sniffer built in Lua, designed to capture and filter network traffic based on specific protocols, IPs, or ports. It's a great tool for analyzing traffic patterns or filtering out noise from your network captures.

## Features:
- Captures and inspects network packets
- Filters traffic by protocol, IP, or port
- Customizable Lua-based packet processing
- Compatible with `libpcap` or `tshark`

## Installation:
1. Install Lua and the `libpcap` Lua bindings.
2. Clone this repository.
3. Run `lua packetsift.lua` with appropriate capture filters.

## Usage:
```bash
lua packetsift.lua --protocol tcp --port 80
