import pandas as pd
import numpy as np
from keras.models import Sequential
from keras.layers import Dense, Conv1D, Flatten, Dropout
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from keras.utils import to_categorical
import joblib
import os

# data_packet = pd.read_csv('packet_info.csv')

# # label 추가 하고 전부 normal로 설정
# data_packet['label'] = 'normal'


# 컬럼 이름 설정
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate', 'label', 'difficulty_level']

# 데이터 불러오기 및 'difficulty_level' 컬럼 삭제
data = pd.read_csv('NSL-KDD/KDDTrain+.txt', names=columns, header=None)
data2 = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)
data.drop(['difficulty_level'], axis=1, inplace=True)
data2.drop(['difficulty_level'], axis=1, inplace=True)

# 데이터 합치기
data = pd.concat([data, data2])

# 공격 유형별로 레이블 지정
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# 레이블 업데이트 부분 수정
data['label'] = data['label'].map(lambda x: attack_types.get(x, x.upper()))

# 데이터 전처리
le = LabelEncoder()
data['label'] = le.fit_transform(data['label'])
data_labels_one_hot = to_categorical(data['label'])

# 레이블 인코더 저장
if not os.path.exists('model_artifacts'): os.makedirs('model_artifacts')
joblib.dump(le, 'model_artifacts/le_label_DNN.pkl')

# 프로토콜, 서비스, 플래그 인코딩 및 스케일링
for column in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    data[column] = le.fit_transform(data[column])
    joblib.dump(le, f'model_artifacts/le_{column}_DNN.pkl')

scaler = MinMaxScaler()
X = scaler.fit_transform(data.drop('label', axis=1))
joblib.dump(scaler, 'model_artifacts/scaler_DNN.pkl')

# 데이터 분할
X_train, X_test, y_train, y_test = train_test_split(X, data_labels_one_hot, test_size=0.2, random_state=42)

# 다중 분류를 위한 DNN 모델 구성
model = Sequential([
    Dense(512, input_dim=X_train.shape[1], activation='relu'),  # 입력 레이어
    Dropout(0.3),  # 과적합 방지를 위한 드롭아웃
    Dense(256, activation='relu'),  # 은닉 레이어
    Dropout(0.2),  # 과적합 방지를 위한 드롭아웃
    Dense(128, activation='relu'),  # 은닉 레이어
    Dense(data_labels_one_hot.shape[1], activation='softmax')  # 출력 레이어
])

# 모델 컴파일: 옵티마이저, 손실 함수, 평가 지표 설정
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# 모델 훈련: 에포크 수, 배치 크기 설정
model.fit(X_train, y_train, epochs=300, validation_data=(X_test, y_test), batch_size=64)

# 모델 저장
if not os.path.exists('model_artifacts'): 
    os.makedirs('model_artifacts')
model.save('model_artifacts/DNN_multi_class.h5')

# 그래프
import matplotlib.pyplot as plt

# 정확도 그래프
plt.plot(model.history.history['accuracy'])
plt.plot(model.history.history['val_accuracy'])
plt.title('Model Accuracy')
plt.ylabel('Accuracy')
plt.xlabel('Epoch')
plt.legend(['Train', 'Test'], loc='upper left')
plt.show()

