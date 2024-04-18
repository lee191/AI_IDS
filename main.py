from scapy.all import sniff
from packet_processing import process_packet


packet_info = {  
    
    'duration': [],
    'protocol_type': [],
    'service': [],
    'flag': [],
    'src_bytes': [],
    'dst_bytes': [],
    'land': [],
    'wrong_fragment': [],
    'urgent': [],
    'hot': [],
    'num_failed_logins': [],
    'logged_in': [],
    'num_compromised': [],
    'root_shell': [],
    'su_attempted' : [],
    'num_root': [],
    'num_file_creations': [],
    'num_shells': [],
    "num_access_files": [],
    "num_outbound_cmds": [],
    "is_host_login" : [],
    "is_guest_login": [],
    "count": [],
    "srv_count": [],
    "serror_rate": [],
    "srv_serror_rate" : [],
    "rerror_rate" : [],
    "srv_rerror_rate": [],
    "same_srv_rate" : [],
    "diff_srv_rate": [],
    "srv_diff_host_rate": [],
    "dst_host_count": [],
    "dst_host_srv_count": [],
    "dst_host_same_srv_rate": [],
    "dst_host_diff_srv_rate": [],
    "dst_host_same_src_port_rate": [],
    "dst_host_srv_diff_host_rate": [],
    "dst_host_serror_rate": [],
    "dst_host_srv_serror_rate": [],
    "dst_host_rerror_rate": [],
    "dst_host_srv_rerror_rate": [],
}


# 패킷 캡처를 제어하기 위한 전역 변수
capturing = True

def packet_capture_filter(packet):
    # 패킷 캡처를 멈출 조건을 체크
    if not capturing:
        return True  # True를 반환하면 sniff가 패킷 캡처를 멈춤
    return False


## 전체 패킷 캡처 ##
def start_packet_capture():
    try:
        global capturing
        capturing = True
        sniff(prn=lambda packet: process_packet(packet, packet_info), stop_filter=packet_capture_filter, filter="ip")
    except Exception as e:
        print(e)
        
        
#####################      
## 특정 ip 주소만 캡처 ##
#####################

# def start_packet_capture():
#     try:
#         global capturing
#         capturing = True
#         target_ip = "192.168.219.109"
#         filter_condition = f"ip and (src {target_ip} or dst {target_ip})"
#         sniff(prn=lambda packet: process_packet(packet, packet_info), stop_filter=packet_capture_filter, filter=filter_condition)
#     except Exception as e:
#         print(e)

def stop_packet_capture():
    global capturing
    # 캡처 상태를 False로 변경하여 패킷 캡처를 중지
    capturing = False


