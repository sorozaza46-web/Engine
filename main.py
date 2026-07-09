import sys


def main():
    if sys.platform != "win32":
        print("Sheet Onion uses the Win32 memory APIs and only runs on Windows.")
        sys.exit(1)
    import app
    app.main()


if __name__ == "__main__":
    main()
