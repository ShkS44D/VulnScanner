import socket
def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception:
        return None
