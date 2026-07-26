import subprocess


def run(cmd):
    subprocess.run(cmd, check=True)


def enable_ip_forwarding():

    run([
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1"
    ])


def set_ip(interface, ip, prefix):

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


def enable_nat(
    vpn_network,
    internet_interface
):

    run([
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        vpn_network,
        "-o",
        internet_interface,
        "-j",
        "MASQUERADE"
    ])