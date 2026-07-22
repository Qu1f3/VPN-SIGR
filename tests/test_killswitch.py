from firewall.killswitch import KillSwitch


def main():

    ks = KillSwitch()

    print("=" * 50)
    print("ESTADO INICIAL")
    print(ks.status())

    print("\nActivando Kill Switch...")
    ks.enable()
    print(ks.status())

    print("\nBloqueando tráfico...")
    ks.block_traffic()
    print(ks.status())

    print("\nPermitiendo tráfico...")
    ks.allow_traffic()
    print(ks.status())

    print("\nDesactivando Kill Switch...")
    ks.disable()
    print(ks.status())

    print("=" * 50)


if __name__ == "__main__":
    main()