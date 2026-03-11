import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1. Mini-Dataset (4 features: Port, Length, Duration, Protocol)
data = {
    'Dst Port': [443, 80, 22, 443, 80, 3389],
    'Pkt Len Max': [100, 50, 1500, 120, 60, 2000],
    'Flow Duration': [500, 200, 10, 600, 300, 5],
    'Protocol': [6, 6, 17, 6, 6, 17],
    'Label': [0, 0, 1, 0, 0, 1]  # 0 = Normal, 1 = Attack
}
df = pd.DataFrame(data)

# 2. Train the AI
X = df.drop('Label', axis=1)
y = df['Label']
model = RandomForestClassifier(n_estimators=10)
model.fit(X, y)

# 3. Save the Brain
joblib.dump(model, 'ips_model.pkl')
print("✅ Day 1 Success: AI Brain (ips_model.pkl) created!")