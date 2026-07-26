from tunneling.tun_linux import LinuxTun
from tunneling import network


class Adapter:


    def __init__(self):

        self.device = LinuxTun()

        self.name = None
        self.ip = None



    def create(
        self,
        name="VPN-SIGR",
        tunnel_type="VPN"
    ):

        self.name = self.device.create(
            name
        )

        print(
            f"TUN creada: {self.name}"
        )


    def set_ip(
        self,
        ip,
        prefix=24
    ):

        network.set_ip(
            self.name,
            ip,
            prefix
        )

        self.ip = ip



    def enable_internet_sharing(self, interface="enp0s3"):

        network.enable_ip_forwarding()

        network.enable_nat(
            "10.8.0.0/24",
            interface
        )


    def start_session(self):

        pass



    def read_packet(self):

        return self.device.read()



    def write_packet(self, packet):

        self.device.write(packet)



    def close(self):

        self.device.close()



    def __enter__(self):

        return self



    def __exit__(
        self,
        a,
        b,
        c
    ):

        self.close()