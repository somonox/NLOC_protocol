import socket
import struct
import random
import json
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ... (NLOCCrypto, get_local_ip, get_public_addr 동일) ...

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
        pub_ip, pub_port = get_public_addr(self.sock)
        self.sock.settimeout(None) 
        local_ip = get_local_ip()
        
        print(f"🌍 [WAN] {pub_ip}:{pub_port}")
        print(f"🏠 [LAN] {local_ip}:{self.local_port}")
        print("-" * 50)

        # 1. 수신 루프를 먼저 돌림 (입력 전에도 패킷 처리가 가능하게 함)
        threading.Thread(target=self.receive_loop, daemon=True).start()

        # 2. 주소 입력 안내 (이게 떠 있어도 위 스레드는 계속 돌아감)
        print("🔗 상대방 주소를 입력하거나, 상대방이 먼저 연결하기를 기다리세요.")
        
        # 별도의 입력 전용 스레드 가동
        threading.Thread(target=self.input_loop, daemon=True).start()

        # 메인 스레드는 프로그램이 종료되지 않게 대기
        while True:
            time.sleep(1)

    def input_loop(self):
        """사용자 입력을 처리하는 스레드"""
        try:
            peer_wan = input("\n상대방 공인 주소 (IP:Port): ").strip()
            peer_lan = input("상대방 사설 주소 (IP:Port): ").strip()

            for addr_str in [peer_wan, peer_lan]:
                if not addr_str or ":" not in addr_str: continue
                ip, port = addr_str.split(":")
                target = (ip, int(port))
                print(f"🥊 {target}로 'hello' 전송 중...")
                self.sock.sendto(b"hello", target)
            
            # 채팅 메시지 입력 루프
            while True:
                msg = input("나: ")
                if msg == "exit": break
                if self.authenticated and self.crypto.session_key and self.peer_addr:
                    aesgcm = AESGCM(self.crypto.session_key)
                    nonce = bytes(random.getrandbits(8) for _ in range(12))
                    ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
                    payload = {"type": "encryptedPayload", "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
                    self.sock.sendto(json.dumps(payload).encode(), self.peer_addr)
        except EOFError:
            pass

    def receive_loop(self):
        """패킷 수신 및 자동 응답 스레드"""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                text = data.decode('utf-8', errors='ignore').strip()
                
                # 'hello'를 받으면 즉시 Challenge 응답 (주소 입력 여부 상관없음)
                if text == "hello":
                    self.peer_addr = addr
                    self.current_nonce = str(random.getrandbits(128))
                    challenge = {"type": "challenge", "nonce": self.current_nonce}
                    print(f"\n📡 [수신] hello from {addr} -> Challenge 전송")
                    self.sock.sendto(json.dumps(challenge).encode(), addr)
                    continue

                msg = json.loads(text)
                m_type = msg.get("type")

                if m_type == "challenge":
                    print(f"\n📡 [수신] Challenge from {addr} -> Response 전송")
                    self.current_nonce = msg['nonce']
                    pk, ecdh_pk = self.crypto.get_public_keys_hex()
                    response = {"type": "challengeResponse", "signature": self.crypto.sign(self.current_nonce), "publicKey": pk, "ecdhPublicKey": ecdh_pk}
                    self.sock.sendto(json.dumps(response).encode(), addr)

                elif m_type == "challengeResponse":
                    print(f"\n📡 [수신] Response from {addr} -> 검증 완료")
                    host_ecdh_pk = self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    success = {"type": "authSuccess", "ecdhPublicKey": host_ecdh_pk}
                    self.sock.sendto(json.dumps(success).encode(), addr)
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 완료! 상대방({addr})과 연결되었습니다.")

                elif m_type == "authSuccess":
                    self.crypto.compute_shared_secret(msg['ecdhPublicKey'])
                    self.authenticated = True
                    self.peer_addr = addr
                    print(f"✅ 인증 승인됨! 상대방({addr})과 연결되었습니다.")

                elif m_type == "encryptedPayload":
                    if self.crypto.session_key:
                        aesgcm = AESGCM(self.crypto.session_key)
                        decrypted = aesgcm.decrypt(bytes.fromhex(msg['nonce']), bytes.fromhex(msg['ciphertext']), None)
                        print(f"\n🔐 [수신] {decrypted.decode()}")
            except:
                continue