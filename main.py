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
        pk_bytes = self.public_key.public_bytes(
            serialization.Encoding.Raw, 
            serialization.PublicFormat.Raw
        )
        # 가급적 모든 버전에서 지원하는 방식으로 속성 접근
        try:
            fmt = getattr(serialization.PublicFormat, "Uncompressed", 
                  getattr(serialization.PublicFormat, "UncompressedPoint", None))
            ecdh_pk_bytes = self.ecdh_private.public_key().public_bytes(
                serialization.Encoding.X962, fmt
            )
        except Exception as e:
            # 정 안되면 raw하게 추출 (시스템 해킹 스타일)
            ecdh_pk_bytes = self.ecdh_private.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.Uncompressed
            )
        return pk_bytes.hex(), ecdh_pk_bytes.hex()

    def sign(self, message):
        return self.private_key.sign(message.encode()).hex()

    def compute_shared_secret(self, peer_ecdh_pk_hex):
        peer_pk_bytes = bytes.fromhex(peer_ecdh_pk_hex)
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pk_bytes)
        shared_secret = self.ecdh_private.exchange(ec.ECDH(), peer_public_key)
        self.session_key = shared_secret[:32]
        return self.get_public_keys_hex()[1]

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
        # STUN 및 LAN 정보 (하드코딩)
        local_ip = "192.168.123.119"
        local_port = self.sock.getsockname()[1]
        print(f"🚀 NLOC Node Online | 🏠 LAN: {local_ip}:{local_port}")
        
        threading.Thread(target=self.receive_loop, daemon=True).start()

        target = input("\n상대방 주소(IP:Port): ").strip()
        if target and ":" in target:
            ip, port = target.split(":")
            self.peer_addr = (ip, int(port))
            print(f"🥊 {self.peer_addr}로 hello 전송...")
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
                    print(f"👋 hello 수신! (from {addr})")
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    self.sock.sendto(json.dumps({"type": "challenge", "nonce": self.current_nonce}).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                if m_type == "challenge":
                    print(f"📡 Challenge 수신! 응답 생성 중...")
                    pk, epk = self.crypto.get_public_keys_hex()
                    resp = {"type": "challengeResponse", "signature": self.crypto.sign(msg['nonce']), "publicKey": pk, "ecdhPublicKey": epk}
                    self.sock.sendto(json.dumps(resp).encode(), addr)
                    print(f"✅ Response 전송 완료")

                elif m_type == "challengeResponse":
                    print(f"🔐 Response 검증 및 세션 키 생성...")
                    epk = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.sock.sendto(json.dumps({"type": "authSuccess", "ecdhPublicKey": epk}).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✨ 인증 성공! 이제 채팅하세요.")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✨ 인증 완료! 이제 채팅하세요.")

                elif m_type == "encryptedPayload":
                    aesgcm = AESGCM(self.crypto.session_key)
                    dec = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                    print(f"\n🔐 [수신]: {dec.decode()}")

            except Exception as e:
                print(f"❗ 에러 발생: {e}") # 여기서 막히는 원인이 출력됩니다.
                continue

if __name__ == "__main__":
    NLOCNode().start()