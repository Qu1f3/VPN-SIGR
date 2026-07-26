import subprocess



def run(cmd):

    subprocess.run(
        cmd,
        check=True
    )



def set_ip(
    interface,
    ip,
    prefix
):

    run([
        "ip",
        "addr",
        "add",
        f"{ip}/{prefix}",
        "dev",
        interface
    ])


    run([
        "ip",
        "link",
        "set",
        interface,
        "up"
    ])




def enable_forwarding():

    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])




def create_nat(
    ip
):

    network = ip.rsplit(".",1)[0]+".0/24"


    run([
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        network,
        "-j",
        "MASQUERADE"
    ])