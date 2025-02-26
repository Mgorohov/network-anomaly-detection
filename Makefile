MODEL_PATH = models/autoencoder_model.h5
THRESHOLD_PATH = models/anomaly_threshold.pkl
SCALER_PATH = models/scaler.pkl
LOG_FILE = logs/anomalies_log.json

install:
	pip install -r requirements.txt

normalize_trаfic:
	python trafic.py
	python data_normalize.py

train:
	python anomaly_detection.py

detect:
	python realtime_detection.py

clean_logs:
	rm -f $(LOG_FILE)
	echo "Логи аномалий очищены."

clean_models:
	rm -f $(MODEL_PATH) $(THRESHOLD_PATH) $(SCALER_PATH)
	echo "Модели и параметры удалены."

clean_all: clean_logs clean_models
	echo "Все временные файлы удалены."

# Автоматическая проверка наличия модели перед запуском мониторинга
run: $(MODEL_PATH)
	@echo "Запускаем мониторинг..."
	python realtime_detection.py

$(MODEL_PATH):
	@echo "Ошибка: обученная модель не найдена!"
	@echo "Запустите 'make train' для обучения модели."
	@exit 1
