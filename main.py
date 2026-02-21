import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 암호화 및 신원 인증 (이전과 동일) ---
class NLOCCrypto:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
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
        self.session_key = shared_secret[:32]
        return self.ecdh_private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoints
        ).hex()

# --- STUN 직접 구현 ---
def get_public_addr(sock):
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
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 0))
        self.crypto = NLOCCrypto()
        self.peer_addr = None
        self.authenticated = False
        self.current_nonce = ""
        self.local_port = self.sock.getsockname()[1]

    def start(self):
        # 1. 주소 확보
        ext_ip, ext_port = get_public_addr(self.sock)
        self.sock.settimeout(None) 
        
        # 2. 하드코딩된 로컬 IP 사용
        local_ip = "192.168.123.119"

        print(f"\n🚀 NLOC P2P Node Started")
        print(f"🌍 [WAN] {ext_ip}:{ext_port}")
        print(f"🏠 [LAN] {local_ip}:{self.local_port}")
        print("-" * 50)

        threading.Thread(target=self.receive_loop, daemon=True).start()

        # 3. 입력 루프
        print("🔗 상대방 주소를 입력하세요 (IP:Port)")
        try:
            peer_input = input("입력: ").strip()
            if peer_input and ":" in peer_input:
                ip, port = peer_input.split(":")
                self.peer_addr = (ip, int(port))
                # 펀칭 시작
                self.sock.sendto(b"hello", self.peer_addr)
                print(f"🥊 {self.peer_addr}로 'hello' 전송!")

            while True:
                msg = input("")
                if msg == "exit": break
                if self.authenticated and self.crypto.session_key:
                    self.send_encrypted(msg)
                else:
                    print("⚠️ 아직 인증 전입니다.")
        except: pass

    def send_encrypted(self, msg):
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
                
                # 1. RAW 데이터 확인 (이게 찍혀야 패킷이 온 것)
                print(f"\n[DEBUG] 패킷 수신: {addr} -> {text[:50]}...")

                if text == "hello":
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    print(f"📡 [Step 1] hello 수신 -> Challenge 전송")
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                if m_type == "challenge":
                    print(f"📡 [Step 2] Challenge 수신 -> Response 생성 중...")
                    self.current_nonce = msg['nonce']
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    response = {
                        "type": "challengeResponse", 
                        "signature": self.crypto.sign(self.current_nonce), 
                        "publicKey": pk, 
                        "ecdhPublicKey": ecdh_pk
                    }
                    # 중요: 여기서 멈추면 안 됨! 바로 전송
                    self.sock.sendto(json.dumps(response).encode(), addr)
                    print(f"📡 [Step 2] Response 전송 완료")

                elif m_type == "challengeResponse":
                    print(f"📡 [Step 3] Response 수신 -> 검증 시작")
                    host_pub = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_pub}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ [Step 4] 인증 성공 (Host)")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ [Step 4] 인증 완료 (Client)")

                elif m_type == "encryptedPayload":
                    # ... 암호화 수신 로직 ...
                    pass

            except Exception as e:
                print(f"❌ 루프 에러: {e}") # 여기서 에러 원인 파악 가능
                continue

# --- 실행 부분 ---
if __name__ == "__main__":
    node = NLOCNode()
    node.start()