# src/zeek_feature_extractor.py

import time
from collections import deque
import logging
import re
from src.config import NSL_KDD_RELEVANT_COLUMNS, SERVICE_MAPPING, ZEEK_CONN_STATE_TO_NSL_FLAG, ERROR_FLAGS

# Cấu hình logging cho module này
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class ZeekFeatureExtractor:
    def __init__(self, time_window_sec=2.0, host_window_count=100):
        """
        Khởi tạo ZeekFeatureExtractor.
        :param time_window_sec: Khoảng thời gian (giây) cho các đặc trưng time-based (count, rates).
        :param host_window_count: Số lượng kết nối gần nhất cho các đặc trưng host-based.
        """
        self.time_window_sec = time_window_sec
        self.host_window_count = host_window_count

        # Deque để lưu trữ các bản ghi flow gần đây theo thời gian và host
        # Mỗi entry là một dictionary chứa các đặc trưng quan trọng từ log Zeek
        self.recent_flows_time = deque()  # (timestamp, parsed_features)
        self.recent_flows_host = deque()  # (timestamp, parsed_features)

        logging.info(f"Khởi tạo ZeekFeatureExtractor với time_window={time_window_sec}s, host_window={host_window_count} flows.")

    def _map_zeek_conn_state_to_nsl_flag(self, conn_state):
        """Ánh xạ trạng thái kết nối Zeek sang cờ NSL-KDD."""
        return ZEEK_CONN_STATE_TO_NSL_FLAG.get(conn_state, 'OTH')

    def _map_port_to_service(self, protocol, port):
        """Ánh xạ cổng và giao thức sang dịch vụ NSL-KDD."""
        if protocol == 'tcp' and port in SERVICE_MAPPING:
            return SERVICE_MAPPING[port]
        if protocol == 'udp' and port in SERVICE_MAPPING:
            return SERVICE_MAPPING[port]
        # Zeek đôi khi tự động nhận diện dịch vụ và ghi vào cột 'service'.
        # Nếu Zeek có, ưu tiên sử dụng nó.
        # if 'service' in zeek_log_dict and zeek_log_dict['service'] != '-':
        #     return zeek_log_dict['service']
        return 'other' # Mặc định là 'other' nếu không khớp

    def process_zeek_log_entry(self, log_entry_dict):
        """
        Chuyển đổi một dictionary từ log Zeek sang các đặc trưng NSL-KDD.
        Cập nhật bộ đệm và tính toán các đặc trưng thống kê.
        """
        current_ts = float(log_entry_dict.get('ts', time.time())) # Timestamp của dòng log
        
        # 1. Trích xuất các đặc trưng cơ bản trực tiếp từ log Zeek
        features = {}
        try:
            features['duration'] = float(log_entry_dict.get('duration', 0.0))
            features['protocol_type'] = log_entry_dict.get('proto', 'unknown').lower()
            features['service'] = log_entry_dict.get('service', self._map_port_to_service(
                features['protocol_type'], int(log_entry_dict.get('id.resp_p', 0))
            ))
            # Nếu Zeek đã tự động nhận diện dịch vụ, ưu tiên dùng nó.
            if features['service'] == '-': # Zeek dùng '-' cho không có dịch vụ
                features['service'] = self._map_port_to_service(features['protocol_type'], int(log_entry_dict.get('id.resp_p', 0)))


            features['flag'] = self._map_zeek_conn_state_to_nsl_flag(log_entry_dict.get('conn_state', 'OTH'))
            features['src_bytes'] = int(log_entry_dict.get('orig_bytes', 0))
            features['dst_bytes'] = int(log_entry_dict.get('resp_bytes', 0))
            features['land'] = 1 if (log_entry_dict.get('id.orig_h') == log_entry_dict.get('id.resp_h') and \
                                     log_entry_dict.get('id.orig_p') == log_entry_dict.get('id.resp_p')) else 0
            
            # Các đặc trưng content/binary khó trích xuất từ conn.log, mặc định là 0
            features['urgent'] = 0
            features['hot'] = 0
            features['num_failed_logins'] = 0
            features['logged_in'] = 0
            features['num_compromised'] = 0
            features['root_shell'] = 0
            features['su_attempted'] = 0
            features['num_root'] = 0
            features['num_file_creations'] = 0
            features['num_shells'] = 0
            features['num_access_files'] = 0
            features['num_outbound_cmds'] = 0
            features['is_host_login'] = 0
            features['is_guest_login'] = 0
            features['wrong_fragment'] = 0 # Không có trực tiếp trong conn.log

            # Lưu lại một số thông tin cần thiết để tính toán thống kê
            current_flow_info = {
                'ts': current_ts,
                'dest_ip': log_entry_dict.get('id.resp_h'),
                'src_ip': log_entry_dict.get('id.orig_h'),
                'service': features['service'],
                'flag': features['flag']
            }

            # Cập nhật buffer thời gian
            self.recent_flows_time.append(current_flow_info)
            while self.recent_flows_time and \
                  self.recent_flows_time[0]['ts'] < current_ts - self.time_window_sec:
                self.recent_flows_time.popleft()

            # Cập nhật buffer host
            self.recent_flows_host.append(current_flow_info)
            while len(self.recent_flows_host) > self.host_window_count:
                self.recent_flows_host.popleft()

            # 2. Tính toán các đặc trưng thống kê time-based
            current_dest_ip = current_flow_info['dest_ip']
            current_service = current_flow_info['service']

            # Lọc các kết nối liên quan trong cửa sổ thời gian
            relevant_time_flows = [
                f for f in self.recent_flows_time 
                if f['dest_ip'] == current_dest_ip
            ]
            
            features['count'] = len(relevant_time_flows)
            features['srv_count'] = sum(1 for f in relevant_time_flows if f['service'] == current_service)

            total_serror_time = sum(1 for f in relevant_time_flows if f['flag'] in ['S0']) # S0, REJ, RSTO, RSTR for serror in NSL-KDD
            total_rerror_time = sum(1 for f in relevant_time_flows if f['flag'] in ['REJ', 'RSTO', 'RSTR']) # REJ, RSTO, RSTR for rerror in NSL-KDD
            
            features['serror_rate'] = total_serror_time / features['count'] if features['count'] > 0 else 0
            features['srv_serror_rate'] = sum(1 for f in relevant_time_flows if f['service'] == current_service and f['flag'] in ['S0']) / features['srv_count'] if features['srv_count'] > 0 else 0
            features['rerror_rate'] = total_rerror_time / features['count'] if features['count'] > 0 else 0
            features['srv_rerror_rate'] = sum(1 for f in relevant_time_flows if f['service'] == current_service and f['flag'] in ['REJ', 'RSTO', 'RSTR']) / features['srv_count'] if features['srv_count'] > 0 else 0

            features['same_srv_rate'] = features['srv_count'] / features['count'] if features['count'] > 0 else 0
            features['diff_srv_rate'] = (features['count'] - features['srv_count']) / features['count'] if features['count'] > 0 else 0
            
            # srv_diff_host_rate: khó tính chính xác từ conn.log mà không theo dõi các host khác. Tạm thời 0
            features['srv_diff_host_rate'] = 0 

            # 3. Tính toán các đặc trưng thống kê host-based (dựa trên host_window_count)
            relevant_host_flows = [
                f for f in self.recent_flows_host 
                if f['dest_ip'] == current_dest_ip
            ]

            features['dst_host_count'] = len(relevant_host_flows)
            features['dst_host_srv_count'] = sum(1 for f in relevant_host_flows if f['service'] == current_service)

            total_serror_host = sum(1 for f in relevant_host_flows if f['flag'] in ['S0'])
            total_rerror_host = sum(1 for f in relevant_host_flows if f['flag'] in ['REJ', 'RSTO', 'RSTR'])

            features['dst_host_same_srv_rate'] = features['dst_host_srv_count'] / features['dst_host_count'] if features['dst_host_count'] > 0 else 0
            features['dst_host_diff_srv_rate'] = (features['dst_host_count'] - features['dst_host_srv_count']) / features['dst_host_count'] if features['dst_host_count'] > 0 else 0
            
            # dst_host_same_src_port_rate: cần theo dõi src_port của từng flow, phức tạp hơn
            # Tạm thời đặt là 0 hoặc cần thêm logic vào current_flow_info
            features['dst_host_same_src_port_rate'] = 0 
            features['dst_host_srv_diff_host_rate'] = 0 

            features['dst_host_serror_rate'] = total_serror_host / features['dst_host_count'] if features['dst_host_count'] > 0 else 0
            features['dst_host_srv_serror_rate'] = sum(1 for f in relevant_host_flows if f['service'] == current_service and f['flag'] in ['S0']) / features['dst_host_srv_count'] if features['dst_host_srv_count'] > 0 else 0
            features['dst_host_rerror_rate'] = total_rerror_host / features['dst_host_count'] if features['dst_host_count'] > 0 else 0
            features['dst_host_srv_rerror_rate'] = sum(1 for f in relevant_host_flows if f['service'] == current_service and f['flag'] in ['REJ', 'RSTO', 'RSTR']) / features['dst_host_srv_count'] if features['dst_host_srv_count'] > 0 else 0

            features['outcome'] = 'normal' # Luôn là normal cho dữ liệu giám sát

            # Đảm bảo tất cả các cột trong NSL_KDD_RELEVANT_COLUMNS đều có mặt
            # và điền 0 hoặc giá trị mặc định nếu thiếu (cho các cột không trích xuất được)
            final_features = {}
            for col in NSL_KDD_RELEVANT_COLUMNS:
                if col in features:
                    final_features[col] = features[col]
                else:
                    if col in ['protocol_type', 'service', 'flag', 'outcome']:
                        final_features[col] = 'unknown' # Giá trị mặc định cho cột phân loại
                    else:
                        final_features[col] = 0.0 # Giá trị mặc định cho cột số

            return final_features

        except ValueError as ve:
            logging.warning(f"Lỗi chuyển đổi kiểu dữ liệu từ log Zeek: {ve} - log entry: {log_entry_dict}")
            return None
        except Exception as e:
            logging.error(f"Lỗi khi xử lý log Zeek: {e}", exc_info=True)
            return None