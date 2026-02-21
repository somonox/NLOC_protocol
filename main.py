import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

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

def get_public_addr(sock):
    stun_addr = ("stun.l.google.com", 19302)
    buf = bytearray(20)
    buf[0:2] = [0x00, 0x01]
    buf[4:8] = [0x21, 0x12, 0xA4, 0x42]
    transaction_id = bytes(random.getrandbits(8) for _ in range(12))
    buf[8:20] = transaction_id
    
    for _ in range(3):
        sock.sendto(buf, stun_addr)
        try:
            sock.settimeout(2.0) # STUN 응답용 임시 타임아웃
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
        except: continue
    return None, None

class NLOCNode:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0)) 
        self.crypto = NLOCCrypto()
        self.authenticated = False
        self.peer_addr = None
        self.current_nonce = ""
        self.local_port = self.sock.getsockname()[1]

    # ... (앞부분 동일) ...

    def start(self):
        pub_ip, pub_port = get_public_addr(self.sock)
        self.sock.settimeout(None) 
        local_ip = get_local_ip()
        
        print(f"🌍 [WAN] {pub_ip}:{pub_port}")
        print(f"🏠 [LAN] {local_ip}:{self.local_port}")

        threading.Thread(target=self.receive_loop, daemon=True).start()

        peer_wan = input("\n상대방 공인 주소 (IP:Port): ").strip()
        peer_lan = input("상대방 사설 주소 (IP:Port): ").strip()

        # 접속을 시도하는 쪽 (먼저 입력을 마친 쪽)
        for addr_str in [peer_wan, peer_lan]:
            if not addr_str or ":" not in addr_str: continue
            ip, port = addr_str.split(":")
            target = (ip, int(port))
            self.peer_addr = target
            print(f"🥊 {target}로 'hello' 전송...")
            self.sock.sendto(b"hello", target)

        while True:
            msg = input("")
            if msg == "exit": break
            if self.authenticated and self.crypto.session_key and self.peer_addr:
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
                
                # 1. 'hello'를 받으면 나는 Host가 되어 Challenge를 보냄
                if text == "hello":
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    print(f"\n📡 'hello' 수신 -> Challenge 전송 중...")
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                # 2. Challenge를 받으면 나는 Client가 되어 Response를 보냄
                if m_type == "challenge":
                    print(f"📩 Challenge 수신 from {addr} -> Response 전송 중...")
                    self.current_nonce = msg['nonce']
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    response = {
                        "type": "challengeResponse", 
                        "signature": self.crypto.sign(self.current_nonce), 
                        "publicKey": pk, 
                        "ecdhPublicKey": ecdh_pk
                    }
                    self.sock.sendto(json.dumps(response).encode(), addr)

                # 3. Response를 받으면 검증 후 AuthSuccess 전송
                elif m_type == "challengeResponse":
                    print(f"📩 Response 수신 -> 검증 및 AuthSuccess 전송...")
                    host_ecdh_pk = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_ecdh_pk}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료 (Master)! 상대방과 연결되었습니다.")

                # 4. AuthSuccess를 받으면 최종 승인
                elif m_type == "authSuccess":
                    print(f"📩 AuthSuccess 수신!")
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료 (Slave)! 암호화 채널이 열렸습니다.")

                elif m_type == "encryptedPayload":
                    if self.crypto.session_key:
                        aesgcm = AESGCM(self.crypto.session_key)
                        decrypted = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                        print(f"\n🔐 [수신] {decrypted.decode()}")

            except Exception as e:
                continue

if __name__ == "__main__":
    NLOCNode().start()