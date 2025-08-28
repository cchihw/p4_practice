import argparse
import socket
import struct
import threading
from time import sleep

def parse_args():
    parser = argparse.ArgumentParser(description="UDP socket sender/receiver")
    parser.add_argument("--worker_id", type=int, choices=range(1, 101),
                        help="A number from 1 to 100 to decide ID")
    parser.add_argument("--role", type=int, choices=range(0, 2),
                        help="Role in exp, 0 for sender, 1 for receiver")
    parser.add_argument("--bind_port", type=int, default=12345,
                        help="Port to bind the UDP socket (default: 12345)")
    return parser.parse_args()

class worker:
    def __init__(self, worker_id,role,bind_port):
        self.worker_id = worker_id
        self.role = role
        self.dst_ip = '10.0.1.2'
        self.bind_port = bind_port
        self.dst_port = 12345
        self.sock = None
        self.sending_rate = 1024  # in bytes
    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', self.bind_port))
        print(f"[Info] Worker {self.worker_id} listening on port {self.bind_port}")

        self.recv_thread = threading.Thread(target=self.receive_loop)
        self.recv_thread.start()

        if self.role == 0:
            self.target_addr = (self.dst_ip, self.dst_port)
            print(f"[Info] Sender Target: {self.target_addr}")
            self.sender_loop()
        else:
            self.recv_thread.join()

    def receive_loop(self):
        print("[Info] Worker is ready to receive messages.")
        try:
            while True:
                data, addr = self.sock.recvfrom(4096)
                if data:
                    num = struct.unpack('>I', data[:4])[0]
                    print(f"[Recv] From {addr}: {num}")

                    
        except OSError:
            print("[Recv] Socket closed, stopping receive loop.")
    
    def sender_loop(self):
        try:
            payload_size = 1024
            packets_per_sec = self.sending_rate // payload_size
            interval = 1.0 / packets_per_sec  # seconds between packets

            i = 0
            while True:
                payload = b''
                payload = struct.pack('>I',i) + b'\x00' * (payload_size)
                self.sock.sendto(payload, self.target_addr)
                print(f"[Sent] To {self.target_addr}: {i}")
                i += 1
                sleep(interval)

        except KeyboardInterrupt:
            print("\n[Info] Exiting.")
        finally:
            self.sock.close()
            self.recv_thread.join()


def main():
    args = parse_args()
    w = worker(args.worker_id,args.role,args.bind_port)
    w.run()
    
if __name__ == "__main__":
    main()
