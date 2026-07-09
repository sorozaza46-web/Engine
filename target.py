import ctypes
import os
import time

health = ctypes.c_int(100)
mana = ctypes.c_float(50.0)


def main():
    print(f"=== Sheet Onion practice target ===")
    print(f"PID: {os.getpid()}   (attach Sheet Onion to this python.exe)")
    print("Scan for the 'health' integer or 'mana' float, then edit them.\n")
    direction = -1
    while True:
        health.value += direction
        if health.value <= 0 or health.value >= 100:
            direction = -direction
        mana.value = round(mana.value + 0.25, 2)
        if mana.value >= 100:
            mana.value = 0.0
        print(f"\rhealth = {health.value:4d}    mana = {mana.value:7.2f}   "
              f"(addr health=0x{ctypes.addressof(health):X})", end="", flush=True)
        time.sleep(1.0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nbye")
