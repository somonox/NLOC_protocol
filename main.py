import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class NLOCCrypto:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.ecdh_private = ec.generate_private_key(ec.SECP256R1())
        self.session_key = None

    def get_public_keys_hex(self):
        # Ed25519 Public Key
        pk_bytes = self.public_key.public_bytes(
            serialization.Encoding.Raw, 
            serialization.PublicFormat.Raw
        )
        # P-256 ECDH Public Key (Uncompressed Point: 04 + X + Y)
        # 여기서 UncompressedPoint 대신 Uncompressed를 사용합니다.
        ecdh_pk_bytes = self.ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962, 
            serialization.PublicFormat.Uncompressed # 이 부분 수정됨
        )
        return pk_bytes.hex(), ecdh_pk_bytes.hex()

    def sign(self, message):
        return self.private_key.sign(message.encode()).hex()

    def compute_shared_secret(self, peer_ecdh_pk_hex):
        peer_pk_bytes = bytes.fromhex(peer_ecdh_pk_hex)
        # 상대방의 Uncompressed Point로부터 키 복원
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), 
            peer_pk_bytes
        )
        shared_secret = self.ecdh_private.exchange(ec.ECDH(), peer_public_key)
        self.session_key = shared_secret[:32]
        
        return self.ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962, 
            serialization.PublicFormat.Uncompressed
        ).hex()

# --- 네트워크 노드 로직 (나머지는 동일) ---
class NLOCNode:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 0))
        self.crypto = NLOCCrypto()
        self.peer_addr = None
        self.authenticated = False
        self.current_nonce = ""

    def start(self):
        # 1. 주소 확보 (STUN 함수는 이전과 동일하므로 내부 포함)
        stun_addr = ("stun.l.google.com", 19302)
        self.sock.settimeout(2.0)
        buf = bytearray(20)
        buf[0:2] = [0x00, 0x01]
        buf[4:8] = [0x21, 0x12, 0xA4, 0x42]
        buf[8:20] = bytes(random.getrandbits(8) for _ in range(12))
        
        ext_ip, ext_port = None, None
        try:
            self.sock.sendto(buf, stun_addr)
            data, _ = self.sock.recvfrom(1024)
            pos = 20
            while pos < len(data):
                attr_type, attr_len = struct.unpack('!HH', data[pos:pos+4])
                if attr_type in [0x0001, 0x0020]:
                    port = struct.unpack('!H', data[pos+6:pos+8])[0]
                    ip_bytes = list(data[pos+8:pos+12])
                    if attr_type == 0x0020:
                        port ^= 0x2112
                        for j in range(4): ip_bytes[j] ^= buf[4+j]
                    ext_ip, ext_port = ".".join(map(str, ip_bytes)), port
                    break
                pos += 4 + attr_len
        except: pass
        
        self.sock.settimeout(None)
        local_ip = "192.168.123.119" # 하드코딩된 LAN IP
        local_port = self.sock.getsockname()[1]

        print(f"🌍 [WAN] {ext_ip}:{ext_port} | 🏠 [LAN] {local_ip}:{local_port}")
        threading.Thread(target=self.receive_loop, daemon=True).start()

        peer_input = input("\n상대방 주소(IP:Port): ").strip()
        if peer_input and ":" in peer_input:
            ip, port = peer_input.split(":")
            self.peer_addr = (ip, int(port))
            self.sock.sendto(b"hello", self.peer_addr)

        while True:
            msg = input("")
            if msg == "exit": break
            if self.authenticated and self.crypto.session_key:
                aesgcm = AESGCM(self.crypto.session_key)
                nonce = bytes(random.getrandbits(8) for _ in range(12))
                ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
                payload = {"type": "encryptedPayload", "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
                self.sock.sendto(json.dumps(payload).encode(), self.peer_addr)

    def receive_loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                text = data.decode('utf-8', errors='ignore').strip()
                
                if text == "hello":
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                if m_type == "challenge":
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    response = {
                        "type": "challengeResponse", 
                        "signature": self.crypto.sign(msg['nonce']), 
                        "publicKey": pk, 
                        "ecdhPublicKey": ecdh_pk
                    }
                    self.sock.sendto(json.dumps(response).encode(), addr)

                elif m_type == "challengeResponse":
                    host_pub = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_pub}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료! (Host Mode)")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료! (Client Mode)")

                elif m_type == "encryptedPayload":
                    aesgcm = AESGCM(self.crypto.session_key)
                    dec = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                    print(f"\n🔐 [수신] {dec.decode()}")

            except: continue

if __name__ == "__main__":
    NLOCNode().start()