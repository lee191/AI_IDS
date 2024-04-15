import pandas as pd
import matplotlib.pyplot as plt

# 데이터 로드
data_packet = pd.read_csv('all_packets_with_predictions.csv')

# 'timestamp' 열을 datetime 형식으로 변환
data_packet['timestamp'] = pd.to_datetime(data_packet['timestamp'])

# 데이터를 분 단위로 그룹화
data_grouped_minute = data_packet.groupby([pd.Grouper(key='timestamp', freq='T'), 'predicted_label']).size().unstack(fill_value=0)

# 공격 유형별로 시간에 따른 누적 패킷 수를 계산
data_cumulative_minute = data_grouped_minute.cumsum()

# 시간 범위 확인을 위한 출력
start_time = data_packet['timestamp'].min()
end_time = data_packet['timestamp'].max()
print(f"데이터 시작 시간: {start_time}, 종료 시간: {end_time}")

# 누적 패킷 수의 변화를 나타내는 선 그래프 그리기
data_cumulative_minute.plot(figsize=(10, 6))
plt.title('Cumulative Packet Count by Attack Type Over Time (Minute-wise)')
plt.xlabel('Time')
plt.ylabel('Cumulative Packet Count')
plt.legend(title='Attack Type', bbox_to_anchor=(1.05, 1), loc='upper left')
plt.xticks(rotation=45)
plt.tight_layout()

# 그래프 표시
plt.show()


# 공격 유형과 확률에 따른 산점도 그리기
import seaborn as sns
# '%' 문자를 제거하고 실수형으로 변환
data_packet['probability'] = data_packet['probability'].str.replace('%', '').astype(float)

# 데이터를 로드하고 'probability' 열이 문자열이라면 실수형으로 변환
data_packet['probability'] = data_packet['probability'].astype(float)  # 확률 값을 실수형으로 변환

# timestamp 열을 1초 단위로 묶어서 새로운 열 생성
data_packet['timestamp'] = pd.to_datetime(data_packet['timestamp'])
data_packet['second_timestamp'] = data_packet['timestamp'].dt.floor('1S')

# 공격 유형별로 별도의 산점도 그래프 생성 ('o' 마커 사용)
attack_types = data_packet['predicted_label'].unique()

# 각 공격 유형별로 산점도 그래프 생성
for attack_type in attack_types:
    plt.figure(figsize=(10, 7))
    sns.scatterplot(data=data_packet[data_packet['predicted_label'] == attack_type],
                    x='second_timestamp', y='probability', marker='o', s=100)
    plt.title(f'{attack_type} Probability Distribution (1-Second Interval)')
    plt.xlabel('Time (1-Second Interval)')
    plt.ylabel('Probability')
    plt.tight_layout()
    plt.show()