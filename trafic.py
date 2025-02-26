import csv
from scapy.all import sniff
from datetime import datetime

# Имя файла для сохранения данных
csv_filename = "network_traffic.csv"

# Определяем заголовки CSV
csv_headers = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_size"]

# Функция обработки пакетов
def packet_callback(packet):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Временная метка
        src_ip = packet[0][1].src if packet.haslayer("IP") else "N/A"  # IP источника
        dst_ip = packet[0][1].dst if packet.haslayer("IP") else "N/A"  # IP назначения
        src_port = packet.sport if packet.haslayer("TCP") or packet.haslayer("UDP") else "N/A"  # Порт источника
        dst_port = packet.dport if packet.haslayer("TCP") or packet.haslayer("UDP") else "N/A"  # Порт назначения
        protocol = packet[0][1].proto if packet.haslayer("IP") else "N/A"  # Протокол (TCP, UDP, ICMP и т. д.)
        packet_size = len(packet)  # Размер пакета

        # Запись данных в CSV
        with open(csv_filename, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size])

        print(f"Записан пакет: {timestamp}, {src_ip} → {dst_ip}, {protocol}, {packet_size} байт")

    except Exception as e:
        print(f"Ошибка обработки пакета: {e}")

# Создаем CSV-файл с заголовками (если он еще не создан)
with open(csv_filename, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)


# Ввод времени захвата от пользователя (по умолчанию 24 часа)
default_time = 24 * 60 * 60  # 24 часа в секундах
try:
    capture_time = int(input(f"Введите время сбора (секунды, по умолчанию {default_time}): ") or default_time)
except ValueError:
    print("Ошибка ввода! Используется значение по умолчанию.")
    capture_time = default_time

#interface = "wlo1"  # можно сделать сбор по одному интерфейсу нужному нам
#output_file = "captured_traffic.pcap"

print(f"Начинаем захват трафика на {capture_time} секунд...")
packets = sniff(iface=None, timeout=capture_time, prn=packet_callback, store=False) #iface может быть и конкретным интерфейсом нужным нам
print(f"Захват завершен. Данные сохранены в {csv_filename}")

