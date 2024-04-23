from keras.models import Sequential
from keras.layers import Dense, Conv1D, Flatten, Dropout, BatchNormalization
from keras.optimizers import Adam, SGD
from keras.utils import to_categorical
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import os
import joblib

data_packet = pd.read_csv('packet_info.csv')
# # packet_info.csv 불러오기
# data_packet2 = pd.read_csv('packet_info_label.csv')

# label 추가 하고 전부 normal로 설정
data_packet['label'] = 'normal'
# # 저장
# data_packet.to_csv('runing_packet_info.csv', index=False)

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
# data2 = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)
data.drop(['difficulty_level'], axis=1, inplace=True)
# data2.drop(['difficulty_level'], axis=1, inplace=True)


# 공격 유형별로 레이블 지정
attack_types = {
    'normal': 'NORMAL',
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS', 'teardrop': 'DOS',
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'apache2': 'DOS', 'mailbomb': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS', 'worm': 'DOS', 'mscan': 'PROBE', 'saint': 'PROBE', 'httptunnel': 'R2L', 'named': 'R2L', 'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

# 데이터 합치기
# data = pd.concat([data, data_packet])
# data = pd.concat([data, data_packet2])


# 레이블 업데이트 부분 수정
data['label'] = data['label'].map(lambda x: attack_types.get(x, x.upper()))

# 데이터 전처리
le = LabelEncoder()
data['label'] = le.fit_transform(data['label']) 
# normal: 0, DOS: 1, PROBE: 2, R2L: 3, U2R: 4
data_labels_one_hot = to_categorical(data['label'])


# 레이블 인코더 저장
if not os.path.exists('model_artifacts'): os.makedirs('model_artifacts')
joblib.dump(le, 'model_artifacts/le_label2.pkl')

# 프로토콜, 서비스, 플래그 인코딩 및 스케일링
for column in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    data[column] = le.fit_transform(data[column])
    joblib.dump(le, f'model_artifacts/le_{column}2.pkl')
    

scaler = MinMaxScaler()
X = scaler.fit_transform(data.drop('label', axis=1))
joblib.dump(scaler, 'model_artifacts/scaler2.pkl')

# 데이터 분할
X_train, X_test, y_train, y_test = train_test_split(X, data_labels_one_hot, test_size=0.2, random_state=42)

# 모델 구성
model = Sequential([
    Conv1D(filters=128, kernel_size=6, activation='relu', input_shape=(X_train.shape[1], 1)),
    BatchNormalization(),
    Dropout(0.5),
    Conv1D(filters=64, kernel_size=6, activation='relu'),
    BatchNormalization(),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.5),
    Dense(y_train.shape[1], activation='softmax')
])
# 최적화 알고리즘 선택
optimizer = Adam(learning_rate=0.00001)  # SGD 등 다른 최적화 알고리즘으로 변경 가능

# 모델 컴파일
model.compile(optimizer=optimizer, loss='categorical_crossentropy', metrics=['accuracy'])

# 모델 훈련
history = model.fit(X_train, y_train, epochs=1000, validation_split=0.2, batch_size=64)


# 모델 저장
model.save('model_artifacts/CNN_multi_class.h5')

# 시각화
import matplotlib.pyplot as plt

# 정확도 그래프
plt.plot(model.history.history['accuracy'])
plt.plot(model.history.history['val_accuracy'])
plt.title('Model Accuracy')
plt.ylabel('Accuracy')
plt.xlabel('Epoch')
plt.legend(['Train', 'Test'], loc='upper left')
plt.show()

# 손실 그래프
plt.plot(model.history.history['loss'])
plt.plot(model.history.history['val_loss'])
plt.title('Model Loss')
plt.ylabel('Loss')
plt.xlabel('Epoch')
plt.legend(['Train', 'Test'], loc='upper left')
plt.show()


# 모델 평가
loss, accuracy = model.evaluate(X_test, y_test)
print(f'Loss: {loss}, Accuracy: {accuracy}')
