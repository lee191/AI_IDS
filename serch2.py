import pandas as pd

# 데이터 로드
data = pd.read_csv('all_packets_with_predictions.csv')

# src_ip 또는 dst_ip가 125.209.230.135 인 행만 추출
data = data[(data['src_ip'] == '125.209.230.135') | (data['dst_ip'] == '125.209.230.135')]

# 저장
data.to_csv('filtered_packets.csv', index=False)