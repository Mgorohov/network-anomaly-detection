import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

MODEL_PATH = "models/autoencoder_model.h5"
SCALER_PATH = "models/scaler.pkl"
THRESHOLD_PATH = "models/anomaly_threshold.pkl"

# обрабока датасета
print("Загрузка данных...")
data = pd.read_csv("normalized_traffic.csv")

features = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
X = data[features].values

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, df_train, df_test  = train_test_split(X_scaled, test_size=0.2, random_state=42)

joblib.dump(scaler, SCALER_PATH)

print(f"Данные готовы! Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

print("Создание модели автоэнкодера...")

input_dim = X_train.shape[1]

def build_autoencoder(input_dim):
    model = keras.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(16, activation="relu"),
        layers.Dense(8, activation="relu"), 
        layers.Dense(16, activation="relu"),
        layers.Dense(input_dim, activation="sigmoid")  # Восстановление входных данных
    ])
    model.compile(optimizer="adam", loss="mse")
    return model

if os.path.exists(MODEL_PATH):
    print("Загружаем сохраненную модель...")
    autoencoder = keras.models.load_model(MODEL_PATH)
    
    threshold = joblib.load(THRESHOLD_PATH)
else:
    print("Обучаем новую модель автоэнкодера...")
    autoencoder = build_autoencoder(X_train.shape[1])
    autoencoder.fit(X_train, X_train, epochs=20, batch_size=32, validation_data=(X_test, X_test))

    autoencoder.save(MODEL_PATH)
    print("Модель автоэнкодера сохранена!")

print("Определение порога аномальности...")

X_train_pred = autoencoder.predict(X_train)
train_errors = np.mean(np.abs(X_train - X_train_pred), axis=1)

threshold = np.percentile(train_errors, 95) ## 95 процентный персентиль потимальный порог

joblib.dump(threshold, "anomaly_threshold.pkl")
print(f"Порог аномальности: {threshold}")

print("Обнаружение аномалий в тестовых данных...")

X_test_pred = autoencoder.predict(X_test)
test_errors = np.mean(np.abs(X_test - X_test_pred), axis=1)

threshold = joblib.load("anomaly_threshold.pkl")

anomalies = test_errors > threshold

anomalies_df = df_test[anomalies]
anomalies_df.to_csv("anomalies.csv", index=False)

num_anomalies = np.sum(anomalies)
print(f"Аномалий найдено: {num_anomalies} из {len(anomalies)} тестовых примеров")
