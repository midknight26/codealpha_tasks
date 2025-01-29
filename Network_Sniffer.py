import socket
import struct
import platform


def ethernet_header(raw_data):
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
    dest_mac = ":".join(format(byte, "02x") for byte in dest_mac)
    src_mac = ":".join(format(byte, "02x") for byte in src_mac)
    proto = socket.htons(proto)
    return dest_mac, src_mac, proto, raw_data[14:]


def ipv4_header(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("!8xBB2x4s4s", raw_data[:20])
    src = ".".join(map(str, src))
    target = ".".join(map(str, target))
    return version, header_length, ttl, proto, src, target, raw_data[header_length:]


def main():
    # Check platform
    if platform.system() == "Windows":
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("192.168.59.158", 0))  # Bind to all interfaces
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode
    else:
        # For Linux systems
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Packet sniffer started... Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            print("\n=== New Packet ===")

            # Parse Ethernet Header (Linux only)
            if platform.system() != "Windows":
                dest_mac, src_mac, eth_proto, data = ethernet_header(raw_data)
                print(f"Ethernet Frame: \nDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
            else:
                data = raw_data  # On Windows, skip Ethernet header

            # Parse IPv4 Header
            version, header_length, ttl, proto, src, target, payload = ipv4_header(data)
            print(f"IPv4 Packet: \nVersion: {version}, Header Length: {header_length} bytes, TTL: {ttl}")
            print(f"Protocol: {proto}, Source: {src}, Target: {target}")

            # Display first 64 bytes of payload
            print(f"Payload (First 64 bytes): {payload[:64]}")

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        if platform.system() == "Windows":
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # Disable promiscuous mode
        conn.close()


if __name__ == "__main__":
    main()
