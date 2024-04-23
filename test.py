import subprocess
import tempfile

import subprocess
import tempfile

def add_pf_rule(ip_address):
    rule = f"block drop from {ip_address} to any\nblock drop from any to {ip_address}"
    try:
        # 임시 파일에 규칙을 쓰기
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(rule)
            temp_file.write("\n")  # 마지막에 개행 추가
            temp_file_path = temp_file.name
        
        # 임시 파일을 pfctl에 전달하여 규칙 적용
        subprocess.run(["sudo", "pfctl", "-a", "com.apple/250.BlockIPAddress", "-f", temp_file_path], check=True)
        
        print(f"IP {ip_address} has been successfully blocked.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip_address}: {e}")
    finally:
        # 임시 파일 삭제
        if temp_file_path:
            subprocess.run(["rm", temp_file_path])
        

def unblock_ip(ip_address):
    try:
        # 현재 규칙을 백업하는 명령어
        backup_command = "sudo pfctl -a com.apple/250.BlockIPAddress -s rules > /tmp/pf.rules"
        subprocess.run(backup_command, shell=True, check=True)
        
        # 백업된 파일을 읽고 특정 IP 주소에 대한 규칙을 제거
        with open("/tmp/pf.rules", "r") as file:
            lines = file.readlines()
        with open("/tmp/pf.rules", "w") as file:
            for line in lines:
                if ip_address not in line:
                    file.write(line)
        
        # 수정된 규칙을 다시 로드
        load_command = "sudo pfctl -a com.apple/250.BlockIPAddress -f /tmp/pf.rules"
        subprocess.run(load_command, shell=True, check=True)
        
        print(f"Block rule for IP {ip_address} has been successfully removed.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove block rule for IP {ip_address}: {e}")

    
    
def remove_pf_rule(ip_address):
    try:
        # 'com.apple/250.BlockIPAddress' 앵커 내의 모든 규칙을 제거합니다.
        # '-F all' 옵션은 해당 앵커에 설정된 모든 규칙을 제거합니다.
        command = f"sudo pfctl -a com.apple/250.BlockIPAddress -F all"
        
        # 명령 실행
        subprocess.run(command, shell=True, check=True)
        
        # 모든 규칙 제거 성공 메시지 출력
        print(f"All IP block rules have been successfully removed.")
    except subprocess.CalledProcessError as e:
        # 규칙 제거 실패 시 오류 메시지 출력
        print(f"Failed to remove block rules: {e}")


# 블랙리스트 오픈 후 출력
with open('black_list.txt', 'r') as f:
    blacklist = f.read().splitlines()
    # 시간 부분 제거
    blacklist = [ip.split()[0] for ip in blacklist]
    print(blacklist)
    
