import pandas as pd
import numpy as np
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import joblib

###########################################
# NSL-KDD Test 데이터셋을 사용하여 CNN 모델 테스트#
###########################################

# 모델 및 인코더, 스케일러 불러오기
model = load_model('model_artifacts/CNN_multi_class.h5')
le_protocol = joblib.load('model_artifacts/le_protocol_type2.pkl')
le_service = joblib.load('model_artifacts/le_service2.pkl')
le_flag = joblib.load('model_artifacts/le_flag2.pkl')
scaler = joblib.load('model_artifacts/scaler2.pkl')
le_label = joblib.load('model_artifacts/le_label2.pkl')

# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate', 'label', 'difficulty_level']
data_test = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)
data_test = data_test.drop(['label'], axis=1)
data_test = data_test.drop(['difficulty_level'], axis=1)


# 데이터 인코딩 및 스케일링
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])
X_test_scaled = scaler.transform(data_test)
X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

# 모델 예측
predictions = model.predict(X_test_scaled)
predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

# 예측 결과 분석
attack_types = le_label.classes_
attack_counts = pd.value_counts(predictions)
attack_counts.index = [attack_types[i] for i in attack_counts.index]


print("CNN 공격 유형별 탐지 개수:")
print(attack_counts)

############################################################################################################

########################
# packet_info 테스트 CNN #
########################

# 모델 및 인코더, 스케일러 불러오기
model = load_model('model_artifacts/CNN_multi_class.h5')
le_protocol = joblib.load('model_artifacts/le_protocol_type2.pkl')
le_service = joblib.load('model_artifacts/le_service2.pkl')
le_flag = joblib.load('model_artifacts/le_flag2.pkl')
scaler = joblib.load('model_artifacts/scaler2.pkl')
le_label = joblib.load('model_artifacts/le_label2.pkl')

# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate']
data_test = pd.read_csv('packet_info.csv', names=columns, header=None)
# 라벨 열을 제거합니다.
# data_test = data_test.drop(['label'], axis=1)

# 데이터 인코딩 및 스케일링을 위한 예외 처리
dropped_rows_count = 0

# 'protocol_type' 처리
valid_indices = data_test['protocol_type'].isin(le_protocol.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'service' 처리
valid_indices = data_test['service'].isin(le_service.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'flag' 처리
valid_indices = data_test['flag'].isin(le_flag.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 데이터 인코딩
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])

# 스케일링 전에 데이터셋에 샘플이 존재하는지 확인
if data_test.shape[0] > 0:
    X_test_scaled = scaler.transform(data_test)
    X_test_scaled = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)

    # 모델 예측
    predictions = model.predict(X_test_scaled)
    predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

    # 예측 결과 출력
    attack_types = le_label.classes_
    attack_counts = pd.value_counts(predictions)
    attack_counts.index = [attack_types[i] for i in attack_counts.index]
    # packt_info에 라벨을 추가해서 저장
    data_test['label'] = le_label.inverse_transform(predictions)
    # normal빼고 저장
    data_test = data_test[data_test['label'] != 'normal']
    
    data_test.to_csv('packet_info_label.csv', index=False)
    
    
       

    print("CNN 공격 유형별 탐지 개수(개인수집):")
    print(attack_counts)
else:
    print("전처리 과정에서 모든 데이터가 제거되었습니다. 스케일링과 예측을 진행할 수 없습니다.")

##############################################################################################

########################
# packet_info 테스트 DNN #
########################

import pandas as pd
import numpy as np
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import joblib

# 모델 및 인코더, 스케일러 불러오기
model = load_model('model_artifacts/DNN_multi_class.h5')
le_protocol = joblib.load('model_artifacts/le_protocol_type_DNN.pkl')
le_service = joblib.load('model_artifacts/le_service_DNN.pkl')
le_flag = joblib.load('model_artifacts/le_flag_DNN.pkl')
scaler = joblib.load('model_artifacts/scaler_DNN.pkl')
le_label = joblib.load('model_artifacts/le_label_DNN.pkl')

# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate']

data_test = pd.read_csv('packet_info.csv', names=columns, header=None)
# data_test.drop(['difficulty_level'], axis=1, inplace=True)

# 데이터 인코딩 및 스케일링을 위한 예외 처리
dropped_rows_count = 0

# 'protocol_type' 처리
valid_indices = data_test['protocol_type'].isin(le_protocol.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'service' 처리
valid_indices = data_test['service'].isin(le_service.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 'flag' 처리
valid_indices = data_test['flag'].isin(le_flag.classes_)
dropped_rows_count += (~valid_indices).sum()  # 제거되는 행 수를 카운트
data_test = data_test[valid_indices]

# 데이터 인코딩 및 스케일링
# 여기서는 le_protocol, le_service, le_flag를 이미 불러왔다고 가정합니다.
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])

# 스케일링 전에 데이터셋에 샘플이 존재하는지 확인
if data_test.shape[0] > 0:
    X_test_scaled = scaler.transform(data_test)
    
    # 모델 예측
    predictions = model.predict(X_test_scaled)
    predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

    # 예측 결과 출력
    attack_types = le_label.classes_
    attack_counts = pd.value_counts(predictions)
    attack_counts.index = [attack_types[i] for i in attack_counts.index]
    
    print("DNN 공격 유형별 탐지 개수(개인수집):")
    print(attack_counts)
    

else:
    print("전처리 과정에서 모든 데이터가 제거되었습니다. 스케일링과 예측을 진행할 수 없습니다.")
    
print("삭제된 데이터 수 : ", dropped_rows_count)
##############################################################################################

###########################################
# NSL-KDD Test 데이터셋을 사용하여 DNN 모델 테스트#
###########################################


# 테스트 데이터 준비
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
           'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
           'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
           'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
           'dst_host_srv_rerror_rate', 'label', 'difficulty_level']

data_test = pd.read_csv('NSL-KDD/KDDTest+.txt', names=columns, header=None)
data_test = data_test.drop(['label'], axis=1)
data_test.drop(['difficulty_level'], axis=1, inplace=True)


# 데이터 인코딩 및 스케일링
# 여기서는 le_protocol, le_service, le_flag를 이미 불러왔다고 가정합니다.
data_test['protocol_type'] = le_protocol.transform(data_test['protocol_type'])
data_test['service'] = le_service.transform(data_test['service'])
data_test['flag'] = le_flag.transform(data_test['flag'])

# 스케일링 전에 데이터셋에 샘플이 존재하는지 확인
if data_test.shape[0] > 0:
    X_test_scaled = scaler.transform(data_test)
    
    # 모델 예측
    predictions = model.predict(X_test_scaled)
    predictions = np.argmax(predictions, axis=1)  # 가장 높은 확률을 가진 클래스의 인덱스를 가져옵니다.

    # 예측 결과 출력
    attack_types = le_label.classes_
    attack_counts = pd.value_counts(predictions)
    attack_counts.index = [attack_types[i] for i in attack_counts.index]

    print("DNN 공격 유형별 탐지 개수(개인수집):")
    print(attack_counts)
else:
    print("전처리 과정에서 모든 데이터가 제거되었습니다. 스케일링과 예측을 진행할 수 없습니다.")