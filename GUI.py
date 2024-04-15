import os
import sys
import pandas as pd
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QLabel, QHBoxLayout, QMessageBox, QProgressBar
from PyQt5.QtCore import QTimer
from PyQt5.QtChart import QPieSeries, QChart, QChartView
import threading

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
        
    return os.path.join(base_path, relative_path)

class PacketCaptureGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.capture_thread = None

    def init_ui(self):
        # 위젯 설정
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # 메인 레이아웃
        main_layout = QVBoxLayout(central_widget)

        # 상태 및 정보 레이블 레이아웃
        info_layout = QVBoxLayout()
        main_layout.addLayout(info_layout)

        # 캡처 상태 레이블
        self.capture_status_label = QLabel('캡처 준비...', self)
        info_layout.addWidget(self.capture_status_label)

        # 전체 패킷 수 레이블
        self.total_packets_label = QLabel('전체 패킷 수: 계산 중...', self)
        info_layout.addWidget(self.total_packets_label)

        # 공격 유형별 패킷 수 레이블
        self.attack_counts_label = QLabel('공격 유형별 패킷 수: 계산 중... \n', self)
        info_layout.addWidget(self.attack_counts_label)
        
        # 캡처 진행률 표시
        self.capture_progress = QProgressBar(self)
        self.capture_progress.setRange(0, 0)  # 무한 진행률
        self.capture_progress.setVisible(False)  # 초기에 숨김
        main_layout.addWidget(self.capture_progress)

        # 버튼 레이아웃
        button_layout = QHBoxLayout()
        info_layout.addLayout(button_layout)

        # 시작 버튼
        self.btn_start = QPushButton('패킷 캡처 시작', self)
        self.btn_start.clicked.connect(self.start_capture_thread)
        button_layout.addWidget(self.btn_start)
        

        # 중지 버튼
        self.btn_stop = QPushButton('패킷 캡처 중지', self)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_stop.setEnabled(False)  # 초기에 비활성화
        button_layout.addWidget(self.btn_stop)

        # 테이블 및 차트
        self.table_widget = QTableWidget(self)
        main_layout.addWidget(self.table_widget)
        self.chart_view = QChartView(self)
        main_layout.addWidget(self.chart_view)
        
        

        # 타이머 설정
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)
        self.timer.start(1000)  # 1초마다 테이블 업데이트

        # 차트 업데이트 타이머
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self.update_chart)
        self.chart_timer.start(1000)  # 1초마다 차트 업데이트
        

        # 윈도우 설정
        self.setGeometry(500, 500, 1000, 800)
        self.setWindowTitle('패킷 캡처')

        self.show()

    def stop_capture(self):
        from main import stop_packet_capture

        # 패킷 캡처 중지
        stop_packet_capture()
        self.capture_status_label.setText('캡처 정지')
        self.capture_status_label.setStyleSheet("")
        self.capture_progress.setVisible(False)
        self.btn_start.setEnabled(True)
        self.btn_stop.setDisabled(True)

    def start_capture_thread(self):
        from main import start_packet_capture

        # 쓰레드에서 패킷 캡처 시작
        self.capture_status_label.setText('캡처 중...')
        self.capture_status_label.setStyleSheet("background-color: green; color: white;")
        self.capture_progress.setVisible(True)
        self.btn_start.setDisabled(True)
        self.btn_stop.setEnabled(True)
        self.capture_thread = threading.Thread(target=start_packet_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def update_chart(self):
        # 파일이 없을 경우 처리
        if not os.path.exists(resource_path('all_packets_with_predictions.csv')):
            return
        try:
            data = pd.read_csv(resource_path('all_packets_with_predictions.csv'))
            attack_counts = data['predicted_label'].value_counts()

            # 전체 패킷 수를 업데이트합니다.
            self.total_packets_label.setText(f"전체 패킷 수: {len(data)}")
            
            # 공격 유형별 패킷 수를 업데이트합니다.
            attack_details = '\n'.join([f"{attack}: {count}" for attack, count in attack_counts.items()])
            self.attack_counts_label.setText(f"공격 유형별 패킷 수: {attack_details}")

            series = QPieSeries()
            total = sum(attack_counts)
            for attack, count in attack_counts.items():
                slice = series.append(f"{attack} ({count})", count)
                # 비율을 계산하고 레이블에 표시합니다.
                percent = 100 * count / total
                slice.setLabel(f"{attack} {percent:.2f}%")
                slice.setLabelVisible(True)

            chart = QChart()
            chart.addSeries(series)
            chart.setTitle('공격 유형별 비율')
            self.chart_view.setChart(chart)
        except Exception as e:
            QMessageBox.critical(self, "오류", "차트를 업데이트하는 동안 오류가 발생했습니다.")
            print(f"Error updating chart: {e}")


    def update_table(self):
        # 파일이 없을 경우 처리
        if not os.path.exists(resource_path('all_packets_with_predictions.csv')):
            return
        try:
            # CSV 파일을 역순으로 읽어옵니다.
            data = pd.read_csv(resource_path('all_packets_with_predictions.csv'))
            data = data.iloc[::-1]  # 데이터를 역순으로 정렬합니다.

            # 테이블에 데이터를 설정합니다.
            self.table_widget.setRowCount(len(data.index))
            self.table_widget.setColumnCount(len(data.columns))
            self.table_widget.setHorizontalHeaderLabels(data.columns)
            
            for row in range(len(data.index)):
                for col in range(len(data.columns)):
                    item = QTableWidgetItem(str(data.iloc[row, col]))
                    self.table_widget.setItem(row, col, item)
                    
        except Exception as e:
            # 에러가 발생했을 때 처리
            self.text_area.setText(f"파일을 읽는 중 오류가 발생했습니다: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketCaptureGUI()
    sys.exit(app.exec_())
