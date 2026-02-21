import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- 핵심: 소켓 하나로 STUN과 P2P를 모두 처리 ---
class NLOCNode:
    def __init__(self):
        # 1. 소켓 초기화 (재사용 옵션 활성화)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 0)) # 랜덤 포트 점유
        
        self.crypto = NLOCCrypto()
        self.peer_addr = None
        self.authenticated = False
        self.current_nonce = ""

    def get_public_addr(self):
        """Rust 소스에서 썼던 그 방식 그대로 직접 구현"""
        stun_addr = ("stun.l.google.com", 19302)
        self.sock.settimeout(2.0)
        
        # STUN Binding Request 조립
        buf = bytearray(20)
        buf[0:2] = [0x00, 0x01]
        buf[4:8] = [0x21, 0x12, 0xA4, 0x42]
        buf[8:20] = bytes(random.getrandbits(8) for _ in range(12))
        
        try:
            self.sock.sendto(buf, stun_addr)
            data, _ = self.sock.recvfrom(1024)
            # XOR-MAPPED-ADDRESS 파싱
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

    def start(self):
        # 1. 내 주소 확보
        ext_ip, ext_port = self.get_public_addr()
        self.sock.settimeout(None) # 이후에는 무한 대기
        
        local_ip = socket.gethostbyname(socket.gethostname())
        local_port = self.sock.getsockname()[1]

        print(f"🌍 [WAN] {ext_ip}:{ext_port}")
        print(f"🏠 [LAN] {local_ip}:{local_port}")
        print("-" * 50)

        # 2. 수신 스레드 시작
        threading.Thread(target=self.receive_loop, daemon=True).start()

        # 3. 입력 루프 (메인 스레드)
        print("🔗 연결하려면 상대방 주소를 입력하세요 (또는 기다리세요)")
        try:
            target_input = input("상대방 주소 (IP:Port): ").strip()
            if target_input and ":" in target_input:
                ip, port = target_input.split(":")
                self.peer_addr = (ip, int(port))
                self.sock.sendto(b"hello", self.peer_addr)
                print(f"🥊 {self.peer_addr}로 hello 전송!")

            while True:
                msg = input("")
                if msg == "exit": break
                if self.authenticated and self.crypto.session_key:
                    self.send_encrypted(msg)
        except KeyboardInterrupt: pass

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
                raw_text = data.decode('utf-8', errors='ignore').strip()
                
                # 'hello' 수신 처리
                if raw_text == "hello":
                    print(f"\n👋 hello 수신! (from {addr})")
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(raw_text)
                m_type = msg.get("type")

                if m_type == "challenge":
                    print(f"📡 Challenge 수신! 응답 중...")
                    self.current_nonce = msg['nonce']
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    resp = {"type": "challengeResponse", "signature": self.crypto.sign(self.current_nonce), "publicKey": pk, "ecdhPublicKey": ecdh_pk}
                    self.sock.sendto(json.dumps(resp).encode(), addr)

                elif m_type == "challengeResponse":
                    print(f"🔐 Response 수신! 세션 키 생성 중...")
                    host_pub = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_pub}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료! 대화 시작 (Master)")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료! 대화 시작 (Slave)")

                elif m_type == "encryptedPayload":
                    aesgcm = AESGCM(self.crypto.session_key)
                    dec = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                    print(f"\n🔐 [수신] {dec.decode()}")

            except: continue

# --- 암호화 (NLOCCrypto 생략, 이전 코드와 동일) ---
# (공간 절약을 위해 위에 기술된 NLOCCrypto 클래스를 그대로 사용하세요)

if __name__ == "__main__":
    node = NLOCNode()
    node.start()