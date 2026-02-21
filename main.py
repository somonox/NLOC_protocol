import socket
import json
import stun
import threading
import time

def get_my_public_addr():
    print("🌐 STUN 서버를 통해 내 외부 주소 확인 중...")
    try:
        nat_type, external_ip, external_port = stun.get_ip_info(
            stun_host='stun.l.google.com', 
            stun_port=19302
        )
        return external_ip, external_port
    except Exception as e:
        print(f"❌ STUN 에러: {e}")
        return None, None

def receive_thread(sock):
    """상대방으로부터 오는 메시지를 계속 듣는 스레드"""
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            message = data.decode('utf-8')
            print(f"\n📩 [수신] {addr}: {message}")
            if message == "PUNCH_REQUEST":
                sock.sendto("PUNCH_RESPONSE".encode('utf-8'), addr)
        except:
            break

def start_p2p():
    # 1. 내 정보 가져오기
    my_ip, my_port = get_my_public_addr()
    if not my_ip: return

    # 2. UDP 소켓 생성 (STUN에서 썼던 포트 그대로 유지해야 홀이 유지됨)
    # 실제 구현 시 소켓 재사용 설정을 하거나, STUN을 수동 구현해야 하지만
    # 프로토타입용으로 새로 바인딩합니다.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", my_port))

    print(f"\n✅ 내 주소 확인됨: {my_ip}:{my_port}")
    print(f"🔗 상대방에게 알려줄 데이터: {json.dumps({'ip': my_ip, 'port': my_port})}")
    print("-" * 50)

    # 3. 수신 스레드 시작
    threading.Thread(target=receive_thread, args=(sock,), daemon=True).start()

    # 4. 상대방 주소 입력 (QR 찍는 행위를 수동 입력으로 대체)
    print("상대방의 정보를 입력하세요 (IP:Port)")
    peer_input = input("입력 (예: 1.2.3.4:54321): ")
    peer_ip, peer_port = peer_input.split(":")
    peer_addr = (peer_ip, int(peer_port))

    # 5. 홀 펀칭 시작 (상대방이 뚫릴 때까지 반복 전송)
    print(f"🥊 {peer_addr}로 홀 펀칭 시도 중... (아무 키나 눌러 대화 시작)")
    
    def punch():
        for _ in range(10):
            sock.sendto("PUNCH_REQUEST".encode('utf-8'), peer_addr)
            time.sleep(1)

    threading.Thread(target=punch, daemon=True).start()

    # 6. 자유 채팅 (데이터 전송 검증)
    while True:
        msg = input("나: ")
        if msg == "exit": break
        sock.sendto(msg.encode('utf-8'), peer_addr)

if __name__ == "__main__":
    start_p2p()