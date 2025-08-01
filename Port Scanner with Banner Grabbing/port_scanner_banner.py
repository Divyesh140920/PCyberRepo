import socket
import threading

# Target and ports can be customized
target = "127.0.0.1"  # Change this to the IP you want to scan

start_port = 1
end_port = 1024
open_ports = []

# Lock for thread-safe print and list append
print_lock = threading.Lock()

def grab_banner(sock):
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        return banner.decode().strip()
    except:
        return ""

def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock)
            with print_lock:
                print(f"Port {port} is open. Banner: {banner}")
            open_ports.append((port, banner))
        sock.close()
    except Exception as e:
        pass

def main():
    print(f"Starting scan on {target} from port {start_port} to {end_port}...\n")
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\nScan complete.")
    print(f"Open ports found: {len(open_ports)}")
    for port, banner in open_ports:
        print(f"Port {port} : {banner}")

if __name__ == "__main__":
    main()
