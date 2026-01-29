import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

print("⏳ AI Training Shuru... (Dataset load ho raha hai)")

# 1. Dataset Load
columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
           "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
           "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
           "num_shells","num_access_files","num_outbound_cmds","is_host_login",
           "is_guest_login","count","srv_count","serror_rate", "srv_serror_rate",
           "rerror_rate","srv_rerror_rate","same_srv_rate", "diff_srv_rate",
           "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
           "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
           "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
           "dst_host_serror_rate","dst_host_srv_serror_rate",
           "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

df = pd.read_csv("KDDTrain+.txt", names=columns)

# 2. Sirf zaroori columns chuno
data = df[['protocol_type', 'service', 'src_bytes']]

# 3. Text ko Number mein badlo (Encoding)
le_proto = LabelEncoder()
le_service = LabelEncoder()
data.loc[:, 'protocol_type'] = le_proto.fit_transform(data['protocol_type'])
data.loc[:, 'service'] = le_service.fit_transform(data['service'])

# 4. Training (Isolation Forest)
model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
model.fit(data)

# 5. Save Files
joblib.dump(model, 'model.pkl')
joblib.dump(le_proto, 'le_proto.pkl')
joblib.dump(le_service, 'le_service.pkl')
print("✅ Training Khatam! Model ban gaya.")
