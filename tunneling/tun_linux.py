import os
import fcntl
import struct


TUNSETIFF = 0x400454CA

IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class LinuxTun:


    def __init__(self):
        self.fd = None
        self.name = None


    def create(self, name="VPN-SIGR"):

        self.fd = os.open(
            "/dev/net/tun",
            os.O_RDWR
        )


        ifr = struct.pack(
            "16sH",
            name.encode(),
            IFF_TUN | IFF_NO_PI
        )


        result = fcntl.ioctl(
            self.fd,
            TUNSETIFF,
            ifr
        )


        self.name = result[:16].strip(
            b"\x00"
        ).decode()


        return self.name



    def read(self):

        return os.read(
            self.fd,
            65535
        )



    def write(self, packet):

        os.write(
            self.fd,
            packet
        )



    def close(self):

        if self.fd:
            os.close(self.fd)