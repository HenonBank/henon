#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Универсальный менеджер процессов для NanoPi R3S (FriendlyWrt)
Запускает и контролирует все боты, следит за температурой и памятью
"""

import os
import sys
import time
import signal
import subprocess
import logging
import json
import shutil
from datetime import datetime, timedelta
from threading import Thread, Event
from typing import Dict, List, Optional

# ==================== КОНФИГУРАЦИЯ ====================
BASE_PATH = "/mnt/extra/vpn"  # Все скрипты в одной папке
CACHE_PATH = "/mnt/extra/vpn/vpn/json"  # Путь к папке с кешем
LOG_FILE = "/var/log/bot_manager.log"
PID_FILE = "/var/run/bot_manager.pid"
TEMP_SENSOR_PATH = "/sys/class/thermal/thermal_zone0/temp"

# Настройки температурного мониторинга
TEMP_CRITICAL = 47  # Критическая температура (остановка)
TEMP_RESUME = 39    # Температура возобновления
TEMP_CHECK_INTERVAL = 60  # Проверка каждую минуту

# Настройки памяти
MEMORY_THRESHOLD = 1024  # МБ - порог очистки
MEMORY_CHECK_INTERVAL = 60  # Проверка каждую минуту

# Настройки очистки кеша
CACHE_CLEAN_INTERVAL = 24 * 60 * 60  # 24 часа в секундах
CACHE_CLEAN_START_HOUR = 3  # Очистка в 3 часа ночи
CACHE_MAX_AGE_DAYS = 7  # Удалять файлы старше 7 дней

# Список ботов для остановки при перегреве
BOTS_TO_STOP_ON_OVERHEAT = [
    "admin_panel",
    "subscription_checker", 
    "rkn",
    "mirror",
    "blacky_coord"  # Blackyashchik.py coordinator
]

# Список всех ботов для запуска
BOTS = [
    {
        "name": "rkn",
        "command": "python3 rkn.py coordinator --config-dir /mnt/extra/vpn/config --auto-boxes 10 -v",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": True  # Будет остановлен при перегреве
    },
    {
        "name": "blacky_coord",
        "command": "python3 Blackyashchik.py coordinator --port 8081 -v",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": True  # Будет остановлен при перегреве
    },
    {
        "name": "mirror",
        "command": "python3 mirror.py",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": True  # Будет остановлен при перегреве
    },
    {
        "name": "vpn2",
        "command": "python3 vpn2.py",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": False  # НЕ будет остановлен при перегреве
    },
    {
        "name": "admin_panel",
        "command": "python3 admin_panel.py",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": True  # Будет остановлен при перегреве
    },
    {
        "name": "subscription_checker",
        "command": "python3 subscription_checker.py",
        "work_dir": BASE_PATH,
        "auto_restart": True,
        "stop_on_overheat": True  # Будет остановлен при перегреве
    }
]

# ==================== НАСТРОЙКА ЛОГИРОВАНИЯ ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("BotManager")

# ==================== КЛАСС МЕНЕДЖЕРА ====================
class BotManager:
    def __init__(self):
        self.running = True
        self.overheated = False
        self.temp_stopped_bots = []  # Боты, остановленные из-за перегрева
        self.process_status = {}
        self.last_cache_clean = 0  # Время последней очистки кеша
        
        # События для потоков
        self.stop_event = Event()
        
        # Обработчики сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Создаем PID файл
        self.create_pid_file()
        
        # Проверяем screen
        self.check_screen()
        
        # Проверяем директории
        self.check_directories()
        
        # Проверяем папку с кешем
        self.check_cache_directory()
        
        # Логируем список ботов для остановки
        logger.info(f"🔥 Боты для остановки при перегреве: {', '.join(BOTS_TO_STOP_ON_OVERHEAT)}")
    
    def signal_handler(self, signum, frame):
        """Обработка сигналов завершения"""
        logger.info(f"Получен сигнал {signum}, завершаем работу...")
        self.running = False
        self.stop_event.set()
    
    def create_pid_file(self):
        """Создание PID файла"""
        try:
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
            logger.info(f"PID файл создан: {PID_FILE}")
        except Exception as e:
            logger.error(f"Ошибка создания PID файла: {e}")
    
    def check_directories(self):
        """Проверка наличия директорий"""
        if not os.path.exists(BASE_PATH):
            logger.error(f"❌ Директория {BASE_PATH} не существует!")
            sys.exit(1)
        
        # Проверяем наличие скриптов
        for bot in BOTS:
            script_name = bot['command'].split()[1]  # Получаем имя файла
            script_path = os.path.join(BASE_PATH, script_name)
            if not os.path.exists(script_path):
                logger.warning(f"⚠️ Скрипт {script_name} не найден в {BASE_PATH}")
    
    def check_cache_directory(self):
        """Проверка папки с кешем"""
        if not os.path.exists(CACHE_PATH):
            try:
                os.makedirs(CACHE_PATH, exist_ok=True)
                logger.info(f"✅ Создана папка для кеша: {CACHE_PATH}")
            except Exception as e:
                logger.error(f"❌ Не удалось создать папку для кеша: {e}")
    
    def check_screen(self):
        """Проверка наличия screen"""
        try:
            subprocess.run(["which", "screen"], check=True, capture_output=True)
            logger.info("✅ Screen найден")
        except subprocess.CalledProcessError:
            logger.warning("❌ Screen не найден. Пытаемся установить...")
            self.install_screen()
    
    def install_screen(self):
        """Установка screen"""
        try:
            subprocess.run(["opkg", "update"], check=True, timeout=60)
            subprocess.run(["opkg", "install", "screen"], check=True, timeout=60)
            logger.info("✅ Screen успешно установлен")
        except Exception as e:
            logger.error(f"❌ Ошибка установки screen: {e}")
            sys.exit(1)
    
    def get_screen_sessions(self):
        """Получение списка screen сессий"""
        try:
            result = subprocess.run(["screen", "-list"], capture_output=True, text=True)
            return result.stdout
        except:
            return ""
    
    def is_session_running(self, session_name):
        """Проверка, запущена ли screen сессия"""
        sessions = self.get_screen_sessions()
        return f".{session_name}" in sessions
    
    def start_bot(self, bot):
        """Запуск бота в screen сессии"""
        session_name = bot["name"]
        command = bot["command"]
        work_dir = bot["work_dir"]
        
        # Проверяем, не запущена ли уже
        if self.is_session_running(session_name):
            logger.info(f"  ⏭️ {session_name} уже запущен")
            return True
        
        try:
            # Создаем screen сессию
            full_command = f"cd {work_dir} && {command}"
            subprocess.run(
                ["screen", "-dmS", session_name, "sh", "-c", full_command],
                check=True
            )
            
            # Проверяем создание
            time.sleep(2)
            if self.is_session_running(session_name):
                logger.info(f"  ✅ {session_name} запущен")
                return True
            else:
                logger.error(f"  ❌ {session_name} не запустился")
                return False
                
        except Exception as e:
            logger.error(f"  ❌ Ошибка запуска {session_name}: {e}")
            return False
    
    def stop_bot(self, session_name):
        """Остановка бота"""
        if self.is_session_running(session_name):
            try:
                subprocess.run(["screen", "-S", session_name, "-X", "quit"], check=True)
                logger.info(f"  ✅ {session_name} остановлен")
                return True
            except Exception as e:
                logger.error(f"  ❌ Ошибка остановки {session_name}: {e}")
                return False
        return True
    
    def start_all_bots(self):
        """Запуск всех ботов"""
        logger.info("\n🚀 Запуск всех ботов...")
        
        for bot in BOTS:
            self.start_bot(bot)
            time.sleep(1)  # Небольшая задержка между запусками
    
    def stop_all_bots(self):
        """Остановка всех ботов"""
        logger.info("\n🛑 Остановка всех ботов...")
        
        for bot in BOTS:
            self.stop_bot(bot["name"])
            time.sleep(1)
    
    def stop_bots_on_overheat(self):
        """Остановка только указанных ботов при перегреве"""
        logger.info("🔥 Останавливаем ботов из-за перегрева...")
        stopped = []
        
        for bot in BOTS:
            if bot.get("stop_on_overheat", False):
                if self.is_session_running(bot["name"]):
                    self.stop_bot(bot["name"])
                    stopped.append(bot["name"])
                    self.temp_stopped_bots.append(bot["name"])
        
        if stopped:
            logger.info(f"✅ Остановлены: {', '.join(stopped)}")
        else:
            logger.info("ℹ️ Никто из ботов не требовал остановки")
    
    def start_bots_after_overheat(self):
        """Запуск остановленных ботов после охлаждения"""
        logger.info("✅ Температура в норме, запускаем остановленных ботов...")
        started = []
        
        for bot_name in self.temp_stopped_bots:
            for bot in BOTS:
                if bot["name"] == bot_name:
                    if self.start_bot(bot):
                        started.append(bot_name)
                    break
        
        if started:
            logger.info(f"✅ Запущены: {', '.join(started)}")
        
        self.temp_stopped_bots.clear()
    
    def get_temperature(self):
        """Получение температуры CPU"""
        try:
            if os.path.exists(TEMP_SENSOR_PATH):
                with open(TEMP_SENSOR_PATH, 'r') as f:
                    temp_raw = f.read().strip()
                    temp = int(temp_raw) / 1000  # Конвертируем в градусы
                    return temp
            else:
                # Альтернативный метод через команду
                result = subprocess.run(["cat", TEMP_SENSOR_PATH], capture_output=True, text=True)
                if result.returncode == 0:
                    return int(result.stdout.strip()) / 1000
        except Exception as e:
            logger.error(f"Ошибка получения температуры: {e}")
        
        return None
    
    def temperature_monitor(self):
        """Мониторинг температуры"""
        logger.info("🌡️  Запуск мониторинга температуры")
        
        while not self.stop_event.is_set():
            try:
                temp = self.get_temperature()
                
                if temp is not None:
                    logger.info(f"🌡️  Температура CPU: {temp:.1f}°C")
                    
                    # Проверка перегрева
                    if temp >= TEMP_CRITICAL and not self.overheated:
                        logger.warning(f"🔥 КРИТИЧЕСКАЯ ТЕМПЕРАТУРА {temp:.1f}°C! Останавливаем ботов...")
                        self.overheated = True
                        
                        # Останавливаем только указанных ботов
                        self.stop_bots_on_overheat()
                    
                    # Проверка восстановления
                    elif temp <= TEMP_RESUME and self.overheated:
                        logger.info(f"✅ Температура снизилась до {temp:.1f}°C. Возобновляем работу...")
                        self.overheated = False
                        
                        # Запускаем остановленных ботов
                        self.start_bots_after_overheat()
                
                # Ждем перед следующей проверкой
                self.stop_event.wait(TEMP_CHECK_INTERVAL)
                
            except Exception as e:
                logger.error(f"Ошибка в мониторинге температуры: {e}")
                self.stop_event.wait(60)
    
    def get_memory_usage(self):
        """Получение использования памяти"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(':')
                        value = int(parts[1])
                        meminfo[key] = value
            
            total = meminfo['MemTotal'] / 1024
            free = meminfo['MemFree'] / 1024
            available = meminfo.get('MemAvailable', free) / 1024
            used = total - available
            
            return {
                'total_mb': round(total, 1),
                'used_mb': round(used, 1),
                'free_mb': round(free, 1),
                'available_mb': round(available, 1),
                'usage_percent': round((used / total) * 100, 1)
            }
        except Exception as e:
            logger.error(f"Ошибка получения информации о памяти: {e}")
            return None
    
    def clear_memory_cache(self):
        """Очистка кэша памяти"""
        try:
            # Синхронизация диска
            os.sync()
            
            # Очистка кэша
            with open('/proc/sys/vm/drop_caches', 'w') as f:
                f.write('3\n')
            
            logger.info("✅ Кэш памяти очищен")
            return True
        except Exception as e:
            logger.error(f"❌ Ошибка очистки кэша: {e}")
            return False
    
    def memory_monitor(self):
        """Мониторинг памяти и очистка кэша"""
        logger.info("💾 Запуск мониторинга памяти")
        
        while not self.stop_event.is_set():
            try:
                mem_info = self.get_memory_usage()
                
                if mem_info:
                    logger.info(f"💾 Память: {mem_info['used_mb']}/{mem_info['total_mb']} МБ ({mem_info['usage_percent']}%)")
                    
                    # Проверка порога
                    if mem_info['used_mb'] >= MEMORY_THRESHOLD:
                        logger.warning(f"⚠️ Превышен порог памяти: {mem_info['used_mb']} МБ")
                        self.clear_memory_cache()
                    else:
                        # Очищаем кэш каждую минуту в любом случае
                        self.clear_memory_cache()
                
                # Ждем перед следующей проверкой
                self.stop_event.wait(MEMORY_CHECK_INTERVAL)
                
            except Exception as e:
                logger.error(f"Ошибка в мониторинге памяти: {e}")
                self.stop_event.wait(60)
    
    def clean_cache_folder(self):
        """Очистка папки с кешем /mnt/extra/vpn/vpn/json"""
        try:
            if not os.path.exists(CACHE_PATH):
                logger.warning(f"⚠️ Папка кеша не существует: {CACHE_PATH}")
                return False
            
            # Получаем список файлов
            files = os.listdir(CACHE_PATH)
            if not files:
                logger.info(f"📁 Папка кеша пуста: {CACHE_PATH}")
                return True
            
            # Счетчики
            total_files = 0
            total_size = 0
            deleted_files = 0
            deleted_size = 0
            current_time = time.time()
            
            # Анализируем файлы
            for filename in files:
                file_path = os.path.join(CACHE_PATH, filename)
                
                # Пропускаем директории
                if os.path.isdir(file_path):
                    continue
                
                total_files += 1
                file_size = os.path.getsize(file_path)
                total_size += file_size
                
                # Проверяем возраст файла (если нужно удалять старые)
                if CACHE_MAX_AGE_DAYS > 0:
                    file_mtime = os.path.getmtime(file_path)
                    file_age_days = (current_time - file_mtime) / (24 * 3600)
                    
                    if file_age_days > CACHE_MAX_AGE_DAYS:
                        os.remove(file_path)
                        deleted_files += 1
                        deleted_size += file_size
                        logger.debug(f"  Удален старый файл: {filename} ({file_age_days:.1f} дней)")
            
            # Если не удаляем по возрасту, просто очищаем папку
            if CACHE_MAX_AGE_DAYS <= 0:
                for filename in files:
                    file_path = os.path.join(CACHE_PATH, filename)
                    if os.path.isfile(file_path):
                        file_size = os.path.getsize(file_path)
                        os.remove(file_path)
                        deleted_files += 1
                        deleted_size += file_size
            
            # Логируем результат
            logger.info(f"📊 Анализ папки кеша:")
            logger.info(f"   Всего файлов: {total_files}, размер: {self.format_size(total_size)}")
            
            if deleted_files > 0:
                logger.info(f"   ✅ Удалено файлов: {deleted_files}, освобождено: {self.format_size(deleted_size)}")
            else:
                logger.info(f"   ✅ Папка кеша уже чистая")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Ошибка при очистке папки кеша: {e}")
            return False
    
    def format_size(self, size_bytes):
        """Форматирование размера файла"""
        for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} ТБ"
    
    def cache_cleaner_monitor(self):
        """Мониторинг и очистка папки с кешем каждые 24 часа"""
        logger.info(f"🗑️  Запуск очистки кеша (интервал: {CACHE_CLEAN_INTERVAL//3600} часов)")
        
        # Устанавливаем время следующей очистки
        next_clean = time.time() + CACHE_CLEAN_INTERVAL
        
        # Если указан час запуска, корректируем время
        if CACHE_CLEAN_START_HOUR >= 0:
            now = datetime.now()
            target_time = now.replace(hour=CACHE_CLEAN_START_HOUR, minute=0, second=0, microsecond=0)
            
            if target_time <= now:
                target_time += timedelta(days=1)
            
            next_clean = target_time.timestamp()
            logger.info(f"⏰ Плановая очистка в {target_time.strftime('%H:%M')} ежедневно")
        
        while not self.stop_event.is_set():
            try:
                current_time = time.time()
                
                # Проверяем, пора ли чистить
                if current_time >= next_clean:
                    logger.info(f"🧹 Запуск плановой очистки папки кеша...")
                    
                    # Очищаем папку
                    self.clean_cache_folder()
                    
                    # Устанавливаем следующую очистку
                    next_clean = current_time + CACHE_CLEAN_INTERVAL
                    
                    # Логируем следующее время
                    next_time = datetime.fromtimestamp(next_clean)
                    logger.info(f"⏰ Следующая очистка: {next_time.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Проверяем каждые 10 минут
                self.stop_event.wait(600)
                
            except Exception as e:
                logger.error(f"Ошибка в мониторинге кеша: {e}")
                self.stop_event.wait(300)  # 5 минут при ошибке
    
    def process_monitor(self):
        """Мониторинг процессов и перезапуск упавших"""
        logger.info("👁️  Запуск мониторинга процессов")
        
        while not self.stop_event.is_set():
            try:
                # Если система перегрета, не проверяем (боты остановлены намеренно)
                if self.overheated:
                    self.stop_event.wait(30)
                    continue
                
                for bot in BOTS:
                    if not self.is_session_running(bot["name"]):
                        if bot.get("auto_restart", True):
                            # Проверяем, не был ли бот остановлен из-за температуры
                            if bot["name"] in self.temp_stopped_bots:
                                logger.debug(f"⏸️ {bot['name']} остановлен из-за температуры, не перезапускаем")
                                continue
                            
                            logger.warning(f"⚠️ Процесс {bot['name']} упал. Перезапускаем...")
                            self.start_bot(bot)
                        else:
                            logger.info(f"ℹ️ Процесс {bot['name']} не запущен (автозапуск отключен)")
                
                # Проверяем каждые 10 секунд
                self.stop_event.wait(10)
                
            except Exception as e:
                logger.error(f"Ошибка в мониторинге процессов: {e}")
                self.stop_event.wait(30)
    
    def print_status(self):
        """Вывод статуса всех процессов"""
        logger.info("\n" + "="*70)
        logger.info("📊 СТАТУС ПРОЦЕССОВ")
        logger.info("="*70)
        
        # Температура
        temp = self.get_temperature()
        if temp:
            temp_color = "🔴" if temp >= TEMP_CRITICAL else "🟡" if temp >= TEMP_RESUME else "🟢"
            logger.info(f"🌡️  Температура: {temp_color} {temp:.1f}°C")
        
        # Память
        mem = self.get_memory_usage()
        if mem:
            mem_color = "🔴" if mem['used_mb'] >= MEMORY_THRESHOLD else "🟢"
            logger.info(f"💾 Память: {mem_color} {mem['used_mb']}/{mem['total_mb']} МБ ({mem['usage_percent']}%)")
        
        # Информация о кеше
        if os.path.exists(CACHE_PATH):
            try:
                files = os.listdir(CACHE_PATH)
                cache_size = 0
                for f in files:
                    f_path = os.path.join(CACHE_PATH, f)
                    if os.path.isfile(f_path):
                        cache_size += os.path.getsize(f_path)
                
                logger.info(f"🗑️  Кеш-папка: {len(files)} файлов, {self.format_size(cache_size)}")
                
                # Время до следующей очистки
                if hasattr(self, 'last_cache_clean') and self.last_cache_clean > 0:
                    next_clean = self.last_cache_clean + CACHE_CLEAN_INTERVAL
                    time_left = next_clean - time.time()
                    if time_left > 0:
                        hours = int(time_left // 3600)
                        minutes = int((time_left % 3600) // 60)
                        logger.info(f"⏰ Следующая очистка через: {hours}ч {minutes}м")
            except:
                pass
        
        logger.info("-"*70)
        
        # Процессы
        for bot in BOTS:
            running = self.is_session_running(bot["name"])
            
            # Определяем статус
            if not running:
                if bot["name"] in self.temp_stopped_bots:
                    status = "⏸️  TEMP STOP (перегрев)"
                else:
                    status = "❌ STOPPED"
            else:
                if bot.get("stop_on_overheat", False):
                    status = "✅ RUNNING (может быть остановлен при перегреве)"
                else:
                    status = "✅ RUNNING (всегда работает)"
            
            # Отметка о возможности остановки
            stop_mark = "🔥 " if bot.get("stop_on_overheat", False) else "💪 "
            logger.info(f"{stop_mark}{bot['name']}: {status}")
        
        # Список ботов для остановки
        logger.info("-"*70)
        logger.info(f"🔥 Боты для остановки при перегреве: {', '.join(BOTS_TO_STOP_ON_OVERHEAT)}")
        logger.info("="*70)
    
    def run(self):
        """Основной цикл управления"""
        logger.info("="*70)
        logger.info("🚀 ЗАПУСК МЕНЕДЖЕРА БОТОВ")
        logger.info("="*70)
        logger.info(f"📁 Рабочая директория: {BASE_PATH}")
        logger.info(f"🗑️  Папка кеша: {CACHE_PATH}")
        logger.info(f"🌡️  Температура: критическая {TEMP_CRITICAL}°C, возобновление {TEMP_RESUME}°C")
        logger.info(f"💾 Память: порог очистки {MEMORY_THRESHOLD} МБ")
        logger.info(f"⏰ Очистка кеша: каждые {CACHE_CLEAN_INTERVAL//3600} часов")
        logger.info(f"🔥 Останавливаем при перегреве: {', '.join(BOTS_TO_STOP_ON_OVERHEAT)}")
        logger.info("="*70)
        
        # Запускаем всех ботов
        self.start_all_bots()
        
        # Запускаем мониторинги в отдельных потоках
        threads = [
            Thread(target=self.temperature_monitor, name="TempMonitor"),
            Thread(target=self.memory_monitor, name="MemMonitor"),
            Thread(target=self.cache_cleaner_monitor, name="CacheCleaner"),
            Thread(target=self.process_monitor, name="ProcMonitor")
        ]
        
        for t in threads:
            t.daemon = True
            t.start()
        
        # Основной цикл управления
        try:
            while self.running:
                # Выводим статус каждые 5 минут
                self.print_status()
                
                # Ждем 5 минут или пока не будет сигнала остановки
                for _ in range(30):  # 30 * 10 секунд = 5 минут
                    if self.stop_event.wait(10):
                        break
                
        except KeyboardInterrupt:
            logger.info("Получен сигнал прерывания")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Очистка перед выходом"""
        logger.info("\n🧹 Завершение работы...")
        
        # Останавливаем всех ботов
        self.stop_all_bots()
        
        # Удаляем PID файл
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except:
            pass
        
        logger.info("👋 Менеджер остановлен")

# ==================== ОСНОВНАЯ ФУНКЦИЯ ====================
def main():
    """Точка входа"""
    
    # Проверка на уже запущенный экземпляр
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            
            # Проверяем, работает ли процесс
            try:
                os.kill(old_pid, 0)
                logger.error(f"❌ Менеджер уже запущен с PID {old_pid}")
                sys.exit(1)
            except OSError:
                # Процесс не работает, удаляем старый PID файл
                os.remove(PID_FILE)
        except:
            pass
    
    # Создаем и запускаем менеджер
    manager = BotManager()
    
    try:
        manager.run()
    except Exception as e:
        logger.error(f"❌ Критическая ошибка: {e}")
        manager.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()