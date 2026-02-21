import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 암호화 및 신원 인증 모듈 ---
class NLOCCrypto:
    def __init__(self):
        # 신원 증명용 Ed25519 (Rust 소스의 ed25519-dalek 대응)
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        # 세션 키 교환용 P-256 (Rust 소스의 p256 대응)
        self.ecdh_private = ec.generate_private_key(ec.SECP256R1())
        self.session_key = None

    def get_public_keys_hex(self):
        pk_bytes = self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ecdh_pk_bytes = self.ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoints
        )
        return pk_bytes.hex(), ecdh_pk_bytes.hex()

    def sign(self, message):
        return self.private_key.sign(message.encode()).hex()

    def compute_shared_secret(self, peer_ecdh_pk_hex):
        peer_pk_bytes = bytes.fromhex(peer_ecdh_pk_hex)
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pk_bytes)
        shared_secret = self.ecdh_private.exchange(ec.ECDH(), peer_public_key)
        self.session_key = shared_secret[:32] # 256-bit AES Key 도출
        return self.ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoints
        ).hex()

# --- 네트워크 유틸리티 ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_public_addr(sock):
    """STUN 바이트 직접 조립 (Rust 소스 로직 이식)"""
    stun_addr = ("stun.l.google.com", 19302)
    sock.settimeout(2.0)
    buf = bytearray(20)
    buf[0:2] = [0x00, 0x01]
    buf[4:8] = [0x21, 0x12, 0xA4, 0x42]
    buf[8:20] = bytes(random.getrandbits(8) for _ in range(12))
    
    try:
        sock.sendto(buf, stun_addr)
        data, _ = sock.recvfrom(1024)
        pos = 20
        while pos < len(data):
            attr_type = struct.unpack('!H', data[pos:pos+2])[0]
            attr_len = struct.unpack('!H', data[pos+2:pos+4])[0]
            if attr_type in [0x0001, 0x0020]:
                port = struct.unpack('!H', data[pos+6:pos+8])[0]
                ip_bytes = list(data[pos+8:pos+12])
                if attr_type == 0x0020:
                    port ^= 0x2112
                    for j in range(4): ip_bytes[j] ^= buf[4+j]
                return ".".join(map(str, ip_bytes)), port
            pos += 4 + attr_len
    except: pass
    return None, None

# --- 메인 P2P 노드 ---
class NLOCNode:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0))
        self.crypto = NLOCCrypto()
        self.authenticated = False
        self.peer_addr = None
        self.current_nonce = ""
        self.local_port = self.sock.getsockname()[1]

    def start(self):
        # 1. 주소 확보 및 환경 설정
        pub_ip, pub_port = get_public_addr(self.sock)
        self.sock.settimeout(None) # 타임아웃 해제 (Blocking 모드)
        local_ip = get_local_ip()

        print(f"\n🚀 NLOC P2P Node Started")
        print(f"🌍 [WAN] {pub_ip}:{pub_port}")
        print(f"🏠 [LAN] {local_ip}:{self.local_port}")
        print("-" * 50)

        # 2. 비동기 수신 스레드 가동 (입력 대기 중에도 패킷 처리 가능)
        threading.Thread(target=self.receive_loop, daemon=True).start()

        # 3. 비동기 입력 스레드 가동
        threading.Thread(target=self.input_loop, daemon=True).start()

        # 메인 스레드 유지
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 종료합니다.")

    def input_loop(self):
        print("🔗 상대방 주소를 입력하거나, 상대방이 먼저 연결하기를 기다리세요.")
        try:
            peer_wan = input("상대방 공인 주소 (IP:Port): ").strip()
            peer_lan = input("상대방 사설 주소 (IP:Port): ").strip()

            for addr_str in [peer_wan, peer_lan]:
                if not addr_str or ":" not in addr_str: continue
                ip, port = addr_str.split(":")
                target = (ip, int(port))
                self.sock.sendto(b"hello", target)

            while True:
                msg = input("") # 채팅 입력
                if msg == "exit": break
                if self.authenticated and self.crypto.session_key:
                    aesgcm = AESGCM(self.crypto.session_key)
                    nonce = bytes(random.getrandbits(8) for _ in range(12))
                    ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
                    payload = {"type": "encryptedPayload", "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
                    self.sock.sendto(json.dumps(payload).encode(), self.peer_addr)
        except: pass

    def receive_loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                text = data.decode('utf-8', errors='ignore').strip()

                # 'hello' 수신 시 Host 역할 수행
                if text == "hello":
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    print(f"\n📡 [수신] hello from {addr} -> Challenge 전송")
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                # Challenge 수신 시 Client 역할 수행
                if m_type == "challenge":
                    print(f"\n📡 [수신] Challenge -> Response 전송 중...")
                    self.current_nonce = msg['nonce']
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    response = {
                        "type": "challengeResponse", 
                        "signature": self.crypto.sign(self.current_nonce),
                        "publicKey": pk, "ecdhPublicKey": ecdh_pk
                    }
                    self.sock.sendto(json.dumps(response).encode(), addr)

                elif m_type == "challengeResponse":
                    print(f"\n📡 [수신] Response -> 인증 성공!")
                    host_pub = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_pub}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 연결 완료: {addr}")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 승인됨! {addr}와 대화 시작")

                elif m_type == "encryptedPayload":
                    if self.crypto.session_key:
                        aesgcm = AESGCM(self.crypto.session_key)
                        decrypted = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                        print(f"\n🔐 [수신] {decrypted.decode()}")

            except: continue

if __name__ == "__main__":
    NLOCNode().start()