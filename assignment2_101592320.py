"""
Author: Zahra Nazari
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter allows controlled access to private attributes.
    # Instead of letting any code freely read or modify self.__target, we can add
    # validation logic in the setter (e.g., rejecting empty strings) without changing
    # how the rest of the code accesses the property. This is called encapsulation.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool using super().__init__(target), which means
# it reuses the private __target attribute and its @property getter/setter without
# rewriting them. For example, calling self.target in scan_port() works because
# PortScanner inherits the target property defined in NetworkTool.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        NetworkTool.__del__(self)

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, any connection error (e.g., timeout, refused connection,
        # or unreachable host) would raise an unhandled exception and crash the entire
        # program. Since we're scanning many ports with threads, one failure would stop
        # everything. The try-except lets us handle errors gracefully and continue scanning.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned simultaneously instead of waiting
    # for each one to time out before moving to the next. Without threads, scanning
    # 1024 ports with a 1-second timeout each would take over 17 minutes in the worst
    # case. With threads, all ports are scanned in parallel, completing in roughly 1 second.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, result[0], result[1], result[2], str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    while True:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if not 1 <= start_port <= 1024:
                print("Port must be between 1 and 1024.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    while True:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if not 1 <= end_port <= 1024:
                print("Port must be between 1 and 1024.")
                continue
            if end_port < start_port:
                print("End port must be >= start port.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target)
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, open_ports)

    history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# An Export to CSV feature would allow users to save scan results to a .csv file
# for easy viewing in spreadsheet tools like Excel. It uses a list comprehension
# to build all the CSV rows in one line from the open ports list:
# rows = [f"{p},{st},{svc}" for p, st, svc in open_ports]
# This is cleaner and faster than writing a manual for-loop to build each row.
# Diagram: See diagram_101592320.png in the repository root