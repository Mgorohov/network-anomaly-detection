import pandas as pd
import socket
import struct
from datetime import datetime

# Имя входного и выходного файлов
input_csv = "network_traffic.csv"
output_csv = "normalized_traffic.csv"

# Функция преобразования IP-адресов в числа
def ip_to_int(ip):
    try:
        if pd.isna(ip):  # Проверяем, если NaN
            return 0
        return struct.unpack("!I", socket.inet_aton(str(ip)))[0]
    except OSError:
        return 0  # Для случаев, когда IP = "N/A" или некорректен

# Функция преобразования времени в UNIX-формат
def time_to_unix(timestamp):
    try:
        return int(datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").timestamp())
    except ValueError:
        return 0  # Если время записано некорректно

# Загружаем CSV
df = pd.read_csv(input_csv)

# Преобразуем данные
df["timestamp"] = df["timestamp"].astype(str).apply(time_to_unix)
df["src_ip"] = df["src_ip"].astype(str).apply(ip_to_int)
df["dst_ip"] = df["dst_ip"].astype(str).apply(ip_to_int)
df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0).astype(int)
df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype(int)
df["protocol"] = pd.to_numeric(df["protocol"], errors="coerce").fillna(0).astype(int)

# Сохраняем нормализованные данные
df.to_csv(output_csv, index=False)

print(f"Нормализация завершена! Данные сохранены в {output_csv}")
