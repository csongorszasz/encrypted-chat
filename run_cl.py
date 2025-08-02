import sys

from src import Client


def get_port():
    # get port from command line arguments
    if len(sys.argv) > 1:
        port = sys.argv[1]
        port = int(port)
        if port < 1024 or port > 65535:
            raise ValueError("Port must be between 1024 and 65535")
    else:
        raise ValueError("Please provide port to run on as a command line argument.")
    return port


if __name__ == "__main__":
    try:
        client = Client(get_port())
        client.run()
    except ValueError as e:
        print("Invalid port: {}".format(str(e)))
        sys.exit(1)
