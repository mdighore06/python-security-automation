import socket
from port_scanner import grab_banner

def test_grab_banner_timeout():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.01)
    banner = grab_banner(sock)
    assert banner == "No banner"
    sock.close()
