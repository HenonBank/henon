import os
import requests
from urllib.parse import urlparse, unquote
import mimetypes
import logging
from datetime import datetime
import time
import sys
import shutil

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('download_log.txt', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def clear_download_folder(folder_path):
    """
    Очищает папку загрузки, удаляя все файлы и подпапки
    
    Args:
        folder_path (str): Путь к папке для очистки
    
    Returns:
        bool: True если очистка прошла успешно, False в противном случае
    """
    try:
        if os.path.exists(folder_path):
            logging.info(f"Очистка папки: {folder_path}")
            
            # Подсчитываем количество файлов до удаления
            file_count = 0
            for root, dirs, files in os.walk(folder_path):
                file_count += len(files)
            
            # Удаляем всё содержимое папки
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                    logging.info(f"  Удален файл: {item}")
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    logging.info(f"  Удалена папка: {item}")
            
            logging.info(f"✓ Папка очищена. Удалено {file_count} файлов")
            return True
        else:
            logging.info(f"Папка {folder_path} не существует, создаем новую")
            return True
    except PermissionError:
        logging.error(f"✗ Нет прав на удаление файлов в папке: {folder_path}")
        return False
    except Exception as e:
        logging.error(f"✗ Ошибка при очистке папки {folder_path}: {e}")
        return False

def is_shatakvpn_url(url):
    """Проверяет, является ли URL от ShatakVPN с ConfigForge-V2Ray"""
    return "ShatakVPN" in url and "ConfigForge-V2Ray" in url

def get_shatakvpn_filename(url):
    """
    Формирует имя файла для ShatakVPN URL.
    Извлекает название папки перед 'all.txt'
    Например: из .../configs/us/all.txt -> us_all.txt
    """
    parsed_url = urlparse(url)
    path_parts = [p for p in parsed_url.path.split('/') if p]
    
    # Ищем часть пути, которая заканчивается на 'all.txt'
    for i, part in enumerate(path_parts):
        if part == 'all.txt' and i > 0:
            folder_name = path_parts[i-1]  # Название папки перед all.txt
            return f"{folder_name}_all.txt"
    
    # Если не нашли, возвращаем None
    return None

def get_filename_from_url(url, response=None):
    """
    Определяет имя файла из URL или заголовков ответа
    """
    # Специальная обработка для ShatakVPN
    if is_shatakvpn_url(url):
        shatak_filename = get_shatakvpn_filename(url)
        if shatak_filename:
            logging.info(f"Обнаружен ShatakVPN URL, имя файла: {shatak_filename}")
            return shatak_filename
    
    parsed_url = urlparse(url)
    filename = os.path.basename(unquote(parsed_url.path))
    
    # Если имя файла не определено или это не файл
    if not filename or filename == "/" or '.' not in filename:
        if response and 'content-disposition' in response.headers:
            # Пробуем получить имя из Content-Disposition
            content_disp = response.headers['content-disposition']
            if 'filename=' in content_disp:
                filename = content_disp.split('filename=')[1].strip('"\'')
                return filename
        
        # Генерируем имя на основе времени
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Используем последнюю часть пути
        path_parts = [p for p in parsed_url.path.split('/') if p]
        if path_parts:
            base_name = path_parts[-1].replace('%20', '_').replace('|', '-')
            # Ограничиваем длину и убираем недопустимые символы
            base_name = ''.join(c for c in base_name if c.isalnum() or c in '._- ')[:50]
        else:
            base_name = f"file_{timestamp}"
        
        # Определяем расширение
        if response:
            content_type = response.headers.get('content-type', '').split(';')[0]
            ext = mimetypes.guess_extension(content_type) or '.txt'
        else:
            ext = '.txt'
        
        filename = f"{base_name}{ext}"
    
    # Очищаем имя файла от недопустимых символов
    filename = ''.join(c for c in filename if c.isalnum() or c in '._- ').strip()
    
    return filename

def download_files(urls, download_folder="/mnt/extra/vpn/config"):
    """
    Сначала очищает папку, затем скачивает файлы из списка URL в указанную папку
    
    Args:
        urls (list): Список URL для скачивания
        download_folder (str): Папка для сохранения файлов (по умолчанию /mnt/extra/vpn/config)
    """
    
    # ШАГ 1: Очистка папки загрузки
    if not clear_download_folder(download_folder):
        logging.error("Не удалось очистить папку загрузки. Прерывание операции.")
        return 0, len(urls), 0
    
    # ШАГ 2: Создаем папку для загрузок, если её нет (после очистки)
    if not os.path.exists(download_folder):
        try:
            os.makedirs(download_folder)
            logging.info(f"Создана папка: {download_folder}")
        except PermissionError:
            logging.error(f"Нет прав на создание папки: {download_folder}")
            return 0, len(urls), 0
        except Exception as e:
            logging.error(f"Ошибка при создании папки {download_folder}: {e}")
            return 0, len(urls), 0
    
    # Проверяем права на запись в папку
    if not os.access(download_folder, os.W_OK):
        logging.error(f"Нет прав на запись в папку: {download_folder}")
        return 0, len(urls), 0
    
    successful = 0
    failed = 0
    downloaded_files = []  # Список для хранения путей к скачанным файлам
    
    logging.info(f"\n{'='*50}")
    logging.info(f"НАЧАЛО ЗАГРУЗКИ ФАЙЛОВ В {download_folder}")
    logging.info(f"{'='*50}")
    
    for i, url in enumerate(urls, 1):
        try:
            logging.info(f"[{i}/{len(urls)}] Обрабатываю: {url}")
            
            # Сначала делаем HEAD запрос для получения информации
            head_response = requests.head(url, allow_redirects=True, timeout=10)
            
            # Теперь скачиваем файл
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Получаем имя файла
            filename = get_filename_from_url(url, response)
            filepath = os.path.join(download_folder, filename)
            
            # Сохраняем файл (проверка на дубликаты не нужна, так как папка очищена)
            total_size = 0
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        total_size += len(chunk)
            
            # Добавляем файл в список скачанных
            downloaded_files.append(filepath)
            
            logging.info(f"✓ Скачан: {filename} ({total_size} байт) в {download_folder}")
            successful += 1
            
        except requests.exceptions.RequestException as e:
            logging.error(f"✗ Ошибка сети для {url}: {e}")
            failed += 1
        except PermissionError as e:
            logging.error(f"✗ Нет прав на запись файла для {url}: {e}")
            failed += 1
        except Exception as e:
            logging.error(f"✗ Ошибка для {url}: {e}")
            failed += 1
    
    # Подсчет общего количества строк во всех скачанных файлах
    total_lines = 0
    if downloaded_files:
        logging.info("\n" + "="*50)
        logging.info("ПОДСЧЕТ КОНФИГУРАЦИЙ:")
        for file_path in downloaded_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = sum(1 for line in f if line.strip())  # Считаем только непустые строки
                    total_lines += lines
                    filename = os.path.basename(file_path)
                    logging.info(f"  {filename}: {lines} строк")
            except Exception as e:
                logging.error(f"  Ошибка чтения {os.path.basename(file_path)}: {e}")
    
    # Итоговая статистика
    logging.info(f"\n{'='*50}")
    logging.info(f"Завершено! Успешно: {successful}, Ошибок: {failed}")
    if successful > 0:
        logging.info(f"Общее количество конфигураций: {total_lines}")
    logging.info(f"Файлы сохранены в папке: {download_folder}")
    
    return successful, failed, total_lines

# Обновленный список URL
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
]

def run_download_job():
    """Запускает одну итерацию загрузки"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*60}")
    print(f"ЗАПУСК ЗАГРУЗКИ: {current_time}")
    print(f"{'='*60}")
    print(f"Папка загрузки: /mnt/extra/vpn/config")
    print(f"Всего URL для обработки: {len(URLS)}")
    print(f"{'='*60}")
    
    # Запускаем загрузку
    successful, failed, total_lines = download_files(URLS)
    
    # Дополнительная статистика в лог
    logging.info(f"Итерация завершена в {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return successful, failed, total_lines

def main_loop(interval_minutes=30):
    """
    Основной цикл программы, запускающий загрузку каждые interval_minutes минут
    
    Args:
        interval_minutes (int): Интервал между запусками в минутах
    """
    interval_seconds = interval_minutes * 60  # Переводим минуты в секунды
    interval_hours = interval_minutes / 60  # Для отображения в часах
    
    print(f"\n{'='*60}")
    print("ЗАПУЩЕН РЕЖИМ 24/7")
    print(f"Интервал загрузки: {interval_minutes} минут ({interval_seconds} секунд)")
    print(f"Нажмите Ctrl+C для остановки")
    print(f"{'='*60}\n")
    
    iteration = 1
    total_successful = 0
    total_failed = 0
    total_configs = 0
    
    try:
        while True:
            print(f"\n{'#'*60}")
            print(f"ИТЕРАЦИЯ #{iteration}")
            print(f"Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'#'*60}\n")
            
            # Запускаем загрузку
            successful, failed, configs = run_download_job()
            
            # Обновляем статистику
            total_successful += successful
            total_failed += failed
            total_configs += configs
            
            iteration += 1
            
            # Выводим общую статистику
            print(f"\n{'*'*60}")
            print(f"ОБЩАЯ СТАТИСТИКА:")
            print(f"  Всего итераций: {iteration-1}")
            print(f"  Всего успешных загрузок: {total_successful}")
            print(f"  Всего ошибок: {total_failed}")
            print(f"  Всего конфигураций: {total_configs}")
            print(f"  Среднее конфигураций за итерацию: {total_configs//(iteration-1) if iteration-1 > 0 else 0}")
            print(f"Следующий запуск через {interval_minutes} минут(ы) в {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + interval_seconds))}")
            print(f"{'*'*60}\n")
            
            # Ждем следующий интервал
            time.sleep(interval_seconds)
            
    except KeyboardInterrupt:
        print(f"\n\n{'!'*60}")
        print("ПРОГРАММА ОСТАНОВЛЕНА ПОЛЬЗОВАТЕЛЕМ")
        print(f"Время остановки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Всего выполнено итераций: {iteration-1}")
        print(f"Всего успешных загрузок: {total_successful}")
        print(f"Всего ошибок: {total_failed}")
        print(f"Всего конфигураций: {total_configs}")
        print(f"{'!'*60}")
        sys.exit(0)

if __name__ == "__main__":
    # Параметры
    DOWNLOAD_INTERVAL_MINUTES = 30  # Интервал в минутах
    
    # Проверяем, передан ли аргумент командной строки для одноразового запуска
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # Одноразовый запуск
        print("="*60)
        print("Загрузчик файлов (одноразовый запуск)")
        print("="*60)
        print(f"Папка загрузки: /mnt/extra/vpn/config")
        print(f"Всего URL для обработки: {len(URLS)}")
        print("="*60)
        
        # Запускаем загрузку
        download_files(URLS)
        
        print("\nНажмите Enter для выхода...")
        input()
    else:
        # Запуск в режиме 24/7 с интервалом 30 минут
        main_loop(DOWNLOAD_INTERVAL_MINUTES)