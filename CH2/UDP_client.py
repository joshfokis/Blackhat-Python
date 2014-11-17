import socket

target_host = "192.168.0.12"
target_port = 80

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client.sendto("AAABBBCCC", (target_host, target_port))

data, addr = client.recvfrom(4096)

print data