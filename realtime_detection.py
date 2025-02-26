import pandas as pd
import numpy as np
import joblib
import struct
import socket
import json
from datetime import datetime
from scapy.all import sniff
#import os
#os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.losses import MeanSquaredError
from sklearn.preprocessing import MinMaxScaler

print("Загрузка модели автоэнкодера и порога аномальности...")

autoencoder = load_model("models/autoencoder_model.h5", custom_objects={"mse": MeanSquaredError()})
threshold = joblib.load("models/anomaly_threshold.pkl")
scaler = joblib.load("models/scaler.pkl")

log_file = "logs/anomalies_log.json"

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def packet_to_features(packet):
    """Извлекает признаки из сетевого пакета"""
    try:
        src_ip = ip_to_int(packet[0][1].src)
        dst_ip = ip_to_int(packet[0][1].dst)
        src_port = packet[0][2].sport if packet.haslayer("TCP") or packet.haslayer("UDP") else 0
        dst_port = packet[0][2].dport if packet.haslayer("TCP") or packet.haslayer("UDP") else 0
        protocol = packet[0][1].proto
    except Exception as e:
        return None  # Пропускаем некорректные пакеты

    return [src_ip, dst_ip, src_port, dst_port, protocol]

def process_packet(packet):
    """Обрабатывает входящий пакет"""
    features = packet_to_features(packet)
    if features is None:
        return

    features = np.array(features).reshape(1, -1)
    features_scaled = scaler.transform(features)

    reconstructed = autoencoder.predict(features_scaled)
    error = np.mean(np.abs(features_scaled - reconstructed))

    if error > threshold:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        anomaly_data = {
            "timestamp": timestamp,
            "src_ip": packet[0][1].src,
            "dst_ip": packet[0][1].dst,
            "src_port": features[0][2],
            "dst_port": features[0][3],
            "protocol": features[0][4],
            "error": error
        }

        print(f"⚠️ Аномалия! {anomaly_data}")

        # Запись в JSON-файл
        try:
            with open(log_file, "r") as f:
                anomalies = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            anomalies = []

        anomalies.append(anomaly_data)

        with open(log_file, "w") as f:
            json.dump(anomalies, f, indent=4)

print("Начинаем мониторинг трафика... (нажмите Ctrl+C для остановки)")
sniff(prn=process_packet, store=False)
