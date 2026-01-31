#!/usr/bin/env python3

import sys
import os
import subprocess
import json
import shutil
import pathlib
import tempfile
import signal
import time
from typing import Optional, Dict, Any
HOME = pathlib.Path.home()
APOLLO_DIR = HOME / ".apollo"
APPS_DIR = APOLLO_DIR / "apps"
CONF_DIR = APOLLO_DIR / "configs"
LOG_DIR = APOLLO_DIR / "logs"
REPO_CACHE = APOLLO_DIR / "repo.json"
VERSION = "2.1.0"

# Цвета для вывода
COLORS = {
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "CYAN": "\033[96m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "END": "\033[0m",
    "BOLD": "\033[1m"
}

#утилиты
def msg(level: str, text: str) -> None:
    """Вывод цветного сообщения"""
    color_map = {
        "SUCCESS": COLORS["GREEN"],
        "INFO": COLORS["CYAN"],
        "WARNING": COLORS["YELLOW"],
        "ERROR": COLORS["RED"],
        "DEBUG": COLORS["MAGENTA"]
    }
    color = color_map.get(level, COLORS["CYAN"])
    print(f"{color}[{level}] {text}{COLORS['END']}")

def ensure_dirs() -> None:
    """Создание необходимых директорий"""
    for d in [APOLLO_DIR, APPS_DIR, CONF_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def check_dep(cmd: str, name: str) -> bool:
    """Проверка наличия зависимости"""
    if shutil.which(cmd) is None:
        msg("ERROR", f"Зависимость '{name}' ({cmd}) не найдена.")
        msg("INFO", f"Установите её: sudo apt install {name.lower()}")
        return False
    return True

def ensure_deps() -> bool:
    """Проверка всех зависимостей"""
    deps = [
        ("lxc", "LXC/LXD"),
        ("wine", "Wine"),
        ("darling", "Darling"),
        ("waydroid", "Waydroid"),
        ("curl", "cURL")
    ]
    
    all_ok = True
    for cmd, name in deps:
        if not check_dep(cmd, name):
            all_ok = False
    
    if not all_ok:
        msg("ERROR", "Не все зависимости установлены")
        msg("INFO", "Рекомендуемые команды установки:")
        msg("INFO", "  sudo apt install lxd wine darling waydroid curl")
        msg("INFO", "  sudo lxd init --auto")
        msg("INFO", "  waydroid init -s GAPPS")
    
    return all_ok

#я заебался ПОДСИСТЕМА LXC 
def subsystem_running() -> bool:
    """Проверка работы LXC-контейнера Apollo"""
    try:
        result = subprocess.run(
            ["lxc", "list", "apollo", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
        containers = json.loads(result.stdout)
        return any(container.get("name") == "apollo" 
                  and container.get("status") == "Running" 
                  for container in containers)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return False

def setup_subsystem() -> bool:
    """Настройка LXC-контейнера"""
    try:
        msg("INFO", "Создание контейнера Apollo...")
        
        # Проверяем существование образа
        subprocess.run(["lxc", "image", "list", "images:ubuntu/22.04"], 
                      check=True, capture_output=True)
        
        # Создаем контейнер
        subprocess.run([
            "lxc", "launch", "images:ubuntu/22.04", "apollo",
            "-c", "security.nesting=true",
            "-c", "security.privileged=true",
            "-c", "linux.kernel_modules=ip_tables,ip6_tables,nf_nat,xt_conntrack"
        ], check=True)
        
        # Ждем запуска сети
        time.sleep(5)
        
        # Обновляем и устанавливаем софт
        msg("INFO", "Установка Wine в контейнере...")
        subprocess.run([
            "lxc", "exec", "apollo", "--",
            "apt", "update", "-y"
        ], check=True)
        
        subprocess.run([
            "lxc", "exec", "apollo", "--",
            "apt", "install", "-y", "wine64", "wine32", "fonts-wine",
            "xauth", "x11-apps", "dbus-x11", "pulseaudio"
        ], check=True)
        
        # Настраиваем X11 forwarding
        subprocess.run([
            "lxc", "config", "set", "apollo",
            "environment.DISPLAY", os.environ.get("DISPLAY", ":0")
        ], check=True)
        
        subprocess.run([
            "lxc", "config", "set", "apollo",
            "environment.PULSE_SERVER", "unix:/home/ubuntu/pulse-native"
        ], check=True)
        
        msg("SUCCESS", "Контейнер Apollo настроен")
        return True
        
    except subprocess.CalledProcessError as e:
        msg("ERROR", f"Ошибка настройки контейнера: {e}")
        return False

def start_subsystem() -> bool:
    """Запуск подсистемы"""
    if not subsystem_running():
        msg("INFO", "Запуск подсистемы Apollo...")
        
        # Проверяем существование контейнера
        result = subprocess.run(
            ["lxc", "list", "apollo", "--format=json"],
            capture_output=True, text=True
        )
        
        containers = json.loads(result.stdout) if result.returncode == 0 else []
        container_exists = any(c.get("name") == "apollo" for c in containers)
        
        if not container_exists:
            if not setup_subsystem():
                return False
        else:
            subprocess.run(["lxc", "start", "apollo"], check=True)
            time.sleep(3)
    
    msg("INFO", "Подсистема готова")
    return True

# ОБНАРУЖЕНИЕ ТИПОВ виндузня
def detect_type(path: str) -> Optional[str]:
    """Определение типа приложения по расширению"""
    path_lower = path.lower()
    
    if path_lower.endswith((".exe", ".msi")):
        return "exe"
    elif path_lower.endswith(".apk"):
        return "apk"
    elif path_lower.endswith((".dmg", ".app", ".pkg")):
        return "macos"
    elif path_lower.endswith((".deb", ".rpm")):
        return "linux"
    elif path_lower.endswith((".sh", ".bash")):
        return "script"
    
    # Проверяем magic bytes для бинарников
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
            if header.startswith(b'MZ'):  # Windows PE
                return "exe"
            elif header.startswith(b'\x7fELF'):  # Linux ELF
                return "linux"
    except:
        pass
    
    return None

#  ЗАПУСК ПРИЛОЖЕНИЙ 
def run_exe(path: str, app_name: str, config: Dict[str, Any]) -> bool:
    """Запуск Windows приложения"""
    try:
        if not start_subsystem():
            return False
        
        # Создаем уникальное имя файла
        exe_name = f"{app_name}_{int(time.time())}.exe"
        container_path = f"/root/{exe_name}"
        
        # Копируем файл в контейнер
        msg("INFO", f"Копирование {path} в контейнер...")
        subprocess.run([
            "lxc", "file", "push", path,
            f"apollo{container_path}"
        ], check=True)
        
        # Подготавливаем переменные окружения
        env_vars = []
        if config.get("environment"):
            for key, value in config["environment"].items():
                env_vars.extend([f"--env", f"{key}={value}"])
        
        # Запускаем приложение
        msg("INFO", f"Запуск {exe_name} через Wine...")
        
        cmd = ["lxc", "exec", "apollo", "--"]
        if env_vars:
            cmd.extend(env_vars)
        cmd.extend(["wine", container_path])
        
        # Запускаем в фоне с перенаправлением вывода
        log_file = LOG_DIR / f"{app_name}_{int(time.time())}.log"
        with open(log_file, "w") as log:
            process = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=log,
                start_new_session=True
            )
        
        msg("INFO", f"Приложение запущено (PID: {process.pid})")
        msg("INFO", f"Логи: {log_file}")
        
        # Сохраняем PID для возможности управления
        pid_file = APOLLO_DIR / "running.pid"
        with open(pid_file, "a") as f:
            f.write(f"{app_name}:{process.pid}\n")
        
        return True
        
    except subprocess.CalledProcessError as e:
        msg("ERROR", f"Ошибка запуска EXE: {e}")
        return False

def run_apk(path: str, app_name: str, config: Dict[str, Any]) -> bool:
    """Запуск Android приложения"""
    try:
        # Проверяем Waydroid
        if shutil.which("waydroid") is None:
            msg("ERROR", "Waydroid не установлен")
            msg("INFO", "Установите: sudo apt install waydroid")
            return False
        
        # Запускаем сессию Waydroid
        msg("INFO", "Запуск Waydroid сессии...")
        subprocess.run(["waydroid", "session", "start"], 
                      check=True, capture_output=True)
        
        # Устанавливаем APK
        msg("INFO", f"Установка {app_name}...")
        subprocess.run(["waydroid", "app", "install", path], check=True)
        
        # Получаем имя пакета
        result = subprocess.run(
            ["aapt", "dump", "badging", path],
            capture_output=True, text=True
        )
        
        package_name = None
        for line in result.stdout.split('\n'):
            if line.startswith("package: name="):
                package_name = line.split("'")[1]
                break
        
        if package_name:
            msg("INFO", f"Запуск пакета {package_name}...")
            subprocess.Popen(
                ["waydroid", "app", "launch", package_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            msg("WARNING", "Не удалось определить имя пакета, запускаем оболочку...")
            subprocess.Popen(
                ["waydroid", "show-full-ui"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        return True
        
    except subprocess.CalledProcessError as e:
        msg("ERROR", f"Ошибка запуска APK: {e}")
        return False

def run_macos(path: str, app_name: str, config: Dict[str, Any]) -> bool:
    """Запуск macOS приложения"""
    try:
        if shutil.which("darling") is None:
            msg("ERROR", "Darling не установлен")
            msg("INFO", "Установите: https://darlinghq.org/")
            return False
        
        msg("INFO", f"Запуск {app_name} через Darling...")
        
        # Для .app директорий
        if path.lower().endswith(".app") and os.path.isdir(path):
            app_path = pathlib.Path(path)
            # Ищем исполняемый файл
            for potential_exe in app_path.rglob("Contents/MacOS/*"):
                if os.access(potential_exe, os.X_OK):
                    subprocess.Popen(
                        ["darling", "shell", str(potential_exe)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    return True
        
        # Для .dmg файлов
        elif path.lower().endswith(".dmg"):
            msg("WARNING", "Монтирование DMG через Darling может потребовать ручной установки")
            subprocess.Popen(
                ["darling", "shell", "hdiutil", "attach", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        
        # Для обычных бинарников
        else:
            subprocess.Popen(
                ["darling", "shell", path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
            
    except Exception as e:
        msg("ERROR", f"Ошибка запуска macOS приложения: {e}")
        return False

#  УПРАВЛЕНИЕ КОНФИГУРАЦИЯМИ э
def load_config(app_name: str) -> Dict[str, Any]:
    """Загрузка конфигурации приложения"""
    conf_file = CONF_DIR / f"{app_name}.conf"
    
    if not conf_file.exists():
        # Конфигурация по умолчанию
        return {
            "name": app_name,
            "type": "unknown",
            "path": "",
            "environment": {},
            "network": "nat",
            "mounts": [],
            "arguments": "",
            "working_dir": "",
            "description": ""
        }
    
    try:
        config = {}
        with open(conf_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    # Специальная обработка для словарей и списков
                    if key == "environment" and value.startswith('{'):
                        try:
                            config[key] = json.loads(value.replace("'", '"'))
                        except:
                            config[key] = {}
                    elif key == "mounts" and value.startswith('['):
                        try:
                            config[key] = json.loads(value.replace("'", '"'))
                        except:
                            config[key] = []
                    else:
                        config[key] = value
        
        return config
    except Exception as e:
        msg("ERROR", f"Ошибка чтения конфигурации: {e}")
        return {}

def save_config(app_name: str, config: Dict[str, Any]) -> bool:
    """Сохранение конфигурации приложения"""
    try:
        conf_file = CONF_DIR / f"{app_name}.conf"
        
        lines = [
            f'# Конфигурация приложения: {app_name}',
            f'# Сгенерировано Apollo {VERSION}',
            '# Измените параметры по необходимости',
            ''
        ]
        
        # Обязательные поля
        lines.append(f'name = "{config.get("name", app_name)}"')
        lines.append(f'type = "{config.get("type", "unknown")}"')
        lines.append(f'path = "{config.get("path", "")}"')
        
        # Опциональные поля
        if config.get("description"):
            lines.append(f'description = "{config["description"]}"')
        
        if config.get("environment"):
            env_str = json.dumps(config["environment"], ensure_ascii=False)
            lines.append(f'environment = {env_str}')
        
        if config.get("mounts"):
            mounts_str = json.dumps(config["mounts"], ensure_ascii=False)
            lines.append(f'mounts = {mounts_str}')
        
        if config.get("network"):
            lines.append(f'network = "{config["network"]}"')
        
        if config.get("arguments"):
            lines.append(f'arguments = "{config["arguments"]}"')
        
        if config.get("working_dir"):
            lines.append(f'working_dir = "{config["working_dir"]}"')
        
        conf_file.write_text('\n'.join(lines))
        return True
        
    except Exception as e:
        msg("ERROR", f"Ошибка сохранения конфигурации: {e}")
        return False

def edit_config_interactive(app_name: str) -> None:
    """Интерактивное редактирование конфигурации"""
    config = load_config(app_name)
    
    if not config.get("path"):
        msg("ERROR", f"Приложение '{app_name}' не найдено или не настроено")
        return
    
    print(f"{COLORS['BOLD']}Редактирование конфигурации: {app_name}{COLORS['END']}")
    print(f"{COLORS['CYAN']}Текущий тип: {config.get('type', 'неизвестен')}{COLORS['END']}")
    print(f"{COLORS['CYAN']}Путь к файлу: {config.get('path', 'не указан')}{COLORS['END']}")
    print()
    
    while True:
        print("Что вы хотите изменить?")
        print("  1. Имя приложения")
        print("  2. Описание")
        print("  3. Переменные окружения")
        print("  4. Аргументы командной строки")
        print("  5. Рабочую директорию")
        print("  6. Настройки сети")
        print("  7. Настройки монтирования")
        print("  8. Показать текущую конфигурацию")
        print("  9. Сохранить и выйти")
        print("  0. Выйти без сохранения")
        
        choice = input(f"{COLORS['YELLOW']}Выберите опцию [0-9]: {COLORS['END']}").strip()
        
        if choice == "1":
            new_name = input("Новое имя приложения: ").strip()
            if new_name:
                config["name"] = new_name
                msg("SUCCESS", "Имя обновлено")
        
        elif choice == "2":
            desc = input("Описание приложения: ").strip()
            config["description"] = desc
            msg("SUCCESS", "Описание обновлено")
        
        elif choice == "3":
            print("Текущие переменные окружения:")
            for key, value in config.get("environment", {}).items():
                print(f"  {key}={value}")
            
            action = input("Добавить (a), удалить (d) или очистить (c)? ").lower()
            
            if action == "a":
                key = input("Имя переменной: ").strip()
                value = input(f"Значение {key}: ").strip()
                if key:
                    config.setdefault("environment", {})[key] = value
                    msg("SUCCESS", f"Переменная {key} добавлена")
            
            elif action == "d":
                key = input("Имя переменной для удаления: ").strip()
                if key in config.get("environment", {}):
                    del config["environment"][key]
                    msg("SUCCESS", f"Переменная {key} удалена")
            
            elif action == "c":
                config["environment"] = {}
                msg("SUCCESS", "Переменные окружения очищены")
        
        elif choice == "4":
            args = input("Аргументы командной строки: ").strip()
            config["arguments"] = args
            msg("SUCCESS", "Аргументы обновлены")
        
        elif choice == "5":
            wd = input("Рабочая директория (оставьте пустым для текущей): ").strip()
            config["working_dir"] = wd if wd else ""
            msg("SUCCESS", "Рабочая директория обновлена")
        
        elif choice == "6":
            print("Текущие настройки сети:", config.get("network", "nat"))
            print("Доступные опции: nat, bridge, host, none")
            network = input("Новый режим сети: ").strip().lower()
            if network in ["nat", "bridge", "host", "none"]:
                config["network"] = network
                msg("SUCCESS", "Настройки сети обновлены")
            else:
                msg("ERROR", "Неверный режим сети")
        
        elif choice == "7":
            print("Текущие точки монтирования:")
            for i, mount in enumerate(config.get("mounts", []), 1):
                print(f"  {i}. {mount}")
            
            action = input("Добавить (a), удалить (d) или очистить (c)? ").lower()
            
            if action == "a":
                host_path = input("Путь на хосте: ").strip()
                container_path = input("Путь в контейнере: ").strip()
                if host_path and container_path:
                    config.setdefault("mounts", []).append(f"{host_path}:{container_path}")
                    msg("SUCCESS", "Точка монтирования добавлена")
            
            elif action == "d":
                try:
                    idx = int(input("Номер для удаления: ").strip()) - 1
                    if 0 <= idx < len(config.get("mounts", [])):
                        removed = config["mounts"].pop(idx)
                        msg("SUCCESS", f"Удалено: {removed}")
                except (ValueError, IndexError):
                    msg("ERROR", "Неверный номер")
            
            elif action == "c":
                config["mounts"] = []
                msg("SUCCESS", "Все точки монтирования очищены")
        
        elif choice == "8":
            print(f"\n{COLORS['CYAN']}Текущая конфигурация:{COLORS['END']}")
            for key, value in config.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for k, v in value.items():
                        print(f"    {k} = {v}")
                elif isinstance(value, list):
                    print(f"  {key}:")
                    for item in value:
                        print(f"    - {item}")
                else:
                    print(f"  {key} = {value}")
            print()
        
        elif choice == "9":
            if save_config(app_name, config):
                msg("SUCCESS", f"Конфигурация '{app_name}' сохранена")
            break
        
        elif choice == "0":
            msg("INFO", "Выход без сохранения")
            break
        
        else:
            msg("ERROR", "Неверный выбор")
        
        print()

def cmd_conf(app_name: str) -> None:
    """Команда редактирования конфигурации"""
    ensure_dirs()
    
    conf_file = CONF_DIR / f"{app_name}.conf"
    if not conf_file.exists():
        msg("ERROR", f"Приложение '{app_name}' не найдено")
        msg("INFO", f"Сначала добавьте его: apollo add <файл> --name {app_name}")
        return
    
    # Определяем редактор
    editor = os.environ.get("EDITOR", os.environ.get("VISUAL", "nano"))
    
    # Предлагаем выбор: интерактивный или текстовый редактор
    print(f"{COLORS['BOLD']}Редактирование конфигурации: {app_name}{COLORS['END']}")
    print("Выберите способ редактирования:")
    print("  1. Интерактивный режим (рекомендуется)")
    print("  2. Текстовый редактор")
    
    choice = input(f"{COLORS['YELLOW']}Выбор [1/2]: {COLORS['END']}").strip()
    
    if choice == "1":
        edit_config_interactive(app_name)
    elif choice == "2":
        msg("INFO", f"Открываю конфигурацию в {editor}...")
        try:
            subprocess.run([editor, str(conf_file)], check=True)
            msg("SUCCESS", "Конфигурация сохранена")
        except subprocess.CalledProcessError as e:
            msg("ERROR", f"Ошибка запуска редактора: {e}")
    else:
        msg("ERROR", "Неверный выбор")

#  ОСНОВНЫЕ КОМАНДЫ 
def cmd_open(target: str) -> None:
    """Запуск приложения"""
    ensure_dirs()
    
    if not ensure_deps():
        return
    
    # Проверяем, является ли target именем приложения или путем
    if not os.path.exists(target):
        # Пробуем найти приложение по имени
        conf_file = CONF_DIR / f"{target}.conf"
        if conf_file.exists():
            config = load_config(target)
            target_path = config.get("path", "")
            
            if not target_path or not os.path.exists(target_path):
                msg("ERROR", f"Файл приложения не найден: {target_path}")
                return
            
            app_name = target
            file_type = config.get("type", detect_type(target_path))
            config["type"] = file_type
            
        else:
            msg("ERROR", f"Файл или приложение '{target}' не найдено")
            return
    else:
        # Запуск по пути
        target_path = os.path.abspath(target)
        app_name = pathlib.Path(target_path).stem
        file_type = detect_type(target_path)
        
        if not file_type:
            msg("ERROR", "Неподдерживаемый тип файла")
            msg("INFO", "Поддерживаемые: .exe, .msi, .apk, .app, .dmg, .deb, .sh")
            return
        
        # Загружаем или создаем конфигурацию
        config = load_config(app_name)
        config.update({
            "name": app_name,
            "type": file_type,
            "path": target_path
        })
    
    msg("INFO", f"Запуск: {app_name} ({file_type})")
    
    # Запускаем в зависимости от типа
    success = False
    if file_type == "exe":
        success = run_exe(target_path, app_name, config)
    elif file_type == "apk":
        success = run_apk(target_path, app_name, config)
    elif file_type == "macos":
        success = run_macos(target_path, app_name, config)
    elif file_type in ["linux", "script"]:
        msg("INFO", "Запуск Linux приложения/скрипта...")
        os.chmod(target_path, 0o755)
        subprocess.Popen([target_path], start_new_session=True)
        success = True
    else:
        msg("ERROR", f"Тип {file_type} не поддерживается для запуска")
    
    if success:
        msg("SUCCESS", f"Приложение '{app_name}' запущено")
        # Сохраняем обновленную конфигурацию
        save_config(app_name, config)
    else:
        msg("ERROR", f"Не удалось запустить '{app_name}'")

def cmd_add(path: str, name: Optional[str] = None) -> None:
    """Добавление приложения"""
    ensure_dirs()
    
    if not os.path.exists(path):
        msg("ERROR", f"Файл не найден: {path}")
        return
    
    app_name = name or pathlib.Path(path).stem
    app_type = detect_type(path)
    
    if not app_type:
        msg("ERROR", "Неподдерживаемый тип файла")
        return
    
    # Создаем директорию приложения
    app_dir = APPS_DIR / app_name
    app_dir.mkdir(exist_ok=True)
    
    # Копируем файл/директорию
    dest_path = app_dir / pathlib.Path(path).name
    
    try:
        if os.path.isdir(path):
            shutil.copytree(path, dest_path, dirs_exist_ok=True)
        else:
            shutil.copy2(path, dest_path)
    except Exception as e:
        msg("ERROR", f"Ошибка копирования: {e}")
        return
    
    # Создаем конфигурацию
    config = {
        "name": app_name,
        "type": app_type,
        "path": str(dest_path),
        "description": f"Добавлено {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "environment": {},
        "mounts": [],
        "network": "nat",
        "arguments": "",
        "working_dir": ""
    }
    
    if save_config(app_name, config):
        msg("SUCCESS", f"Приложение '{app_name}' добавлено")
        msg("INFO", f"Тип: {app_type}, Путь: {dest_path}")
        msg("INFO", f"Настройте: apollo conf {app_name}")
    else:
        msg("ERROR", "Ошибка сохранения конфигурации")

def cmd_remove(app_name: str) -> None:
    """Удаление приложения"""
    ensure_dirs()
    
    conf_file = CONF_DIR / f"{app_name}.conf"
    app_dir = APPS_DIR / app_name
    
    if not conf_file.exists():
        msg("ERROR", f"Приложение '{app_name}' не найдено")
        return
    
    # Подтверждение
    print(f"{COLORS['RED']}Внимание! Будут удалены:{COLORS['END']}")
    print(f"  • Конфигурация: {conf_file}")
    if app_dir.exists():
        print(f"  • Директория приложения: {app_dir}")
    
    confirm = input(f"{COLORS['YELLOW']}Удалить приложение '{app_name}'? [y/N]: {COLORS['END']}")
    
    if confirm.lower() == 'y':
        try:
            conf_file.unlink(missing_ok=True)
            if app_dir.exists():
                shutil.rmtree(app_dir)
            msg("SUCCESS", f"Приложение '{app_name}' удалено")
        except Exception as e:
            msg("ERROR", f"Ошибка удаления: {e}")
    else:
        msg("INFO", "Удаление отменено")

def cmd_list() -> None:
    """Список установленных приложений"""
    ensure_dirs()
    
    configs = list(CONF_DIR.glob("*.conf"))
    
    if not configs:
        msg("INFO", "Нет установленных приложений")
        return
    
    print(f"{COLORS['BOLD']}Установленные приложения:{COLORS['END']}")
    print(f"{'-'*50}")
    
    for conf_file in sorted(configs):
        app_name = conf_file.stem
        config = load_config(app_name)
        
        status = f"{COLORS['GREEN']}✓{COLORS['END']}" if config.get("path") and os.path.exists(config["path"]) else f"{COLORS['RED']}✗{COLORS['END']}"
        app_type = config.get("type", "unknown")
        desc = config.get("description", "")[:50]
        
        print(f"{status} {COLORS['CYAN']}{app_name:<20}{COLORS['END']} "
              f"{COLORS['YELLOW']}{app_type:<10}{COLORS['END']} "
              f"{desc}")
    
    print(f"{'-'*50}")
    msg("INFO", f"Всего приложений: {len(configs)}")

def cmd_info(app_name: Optional[str] = None) -> None:
    """Информация о системе или приложении"""
    ensure_dirs()
    
    if not app_name:
        # Информация о системе
        print(f"{COLORS['BOLD']}Apollo v{VERSION}{COLORS['END']}")
        print(f"{COLORS['CYAN']}Директории:{COLORS['END']}")
        print(f"  Конфигурации: {CONF_DIR}")
        print(f"  Приложения:   {APPS_DIR}")
        print(f"  Логи:         {LOG_DIR}")
        print()
        
        # Зависимости
        print(f"{COLORS['CYAN']}Зависимости:{COLORS['END']}")
        for cmd, name in [("lxc", "LXC"), ("wine", "Wine"), 
                         ("darling", "Darling"), ("waydroid", "Waydroid")]:
            status = f"{COLORS['GREEN']}✓{COLORS['END']}" if shutil.which(cmd) else f"{COLORS['RED']}✗{COLORS['END']}"
            print(f"  {status} {name}")
        print()
        
        # Статистика
        configs = list(CONF_DIR.glob("*.conf"))
        print(f"{COLORS['CYAN']}Статистика:{COLORS['END']}")
        print(f"  Установлено приложений: {len(configs)}")
        print(f"  Контейнер Apollo: {'запущен' if subsystem_running() else 'остановлен'}")
        
    else:
        # Информация о приложении
        config = load_config(app_name)
        
        if not config.get("path"):
            msg("ERROR", f"Приложение '{app_name}' не найдено")
            return
        
        print(f"{COLORS['BOLD']}Приложение: {app_name}{COLORS['END']}")
        print(f"{'-'*50}")
        
        for key, value in config.items():
            if isinstance(value, dict):
                print(f"{COLORS['YELLOW']}{key}:{COLORS['END']}")
                for k, v in value.items():
                    print(f"  {k} = {v}")
            elif isinstance(value, list):
                print(f"{COLORS['YELLOW']}{key}:{COLORS['END']}")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{COLORS['YELLOW']}{key}:{COLORS['END']} {value}")
        
        print(f"{'-'*50}")
        
        # Проверка существования файла
        path = config.get("path", "")
        if path and os.path.exists(path):
            size = os.path.getsize(path)
            msg("INFO", f"Файл существует: {path} ({size:,} байт)")
        else:
            msg("WARNING", f"Файл не найден: {path}")

def cmd_clean() -> None:
    """Очистка временных файлов и логов"""
    ensure_dirs()
    
    # Удаляем старые логи (старше 7 дней)
    deleted_logs = 0
    for log_file in LOG_DIR.glob("*.log"):
        if log_file.stat().st_mtime < time.time() - 7 * 86400:
            try:
                log_file.unlink()
                deleted_logs += 1
            except:
                pass
    
    # Очищаем PID файл
    pid_file = APOLLO_DIR / "running.pid"
    if pid_file.exists():
        pid_file.unlink(missing_ok=True)
    
    msg("SUCCESS", f"Очищено логов: {deleted_logs}")
    msg("INFO", f"Размер директории логов: {sum(f.stat().st_size for f in LOG_DIR.glob('*') if f.is_file()):,} байт")

#  ГЛАВНАЯ ФУНКЦИЯ 
def print_help() -> None:
    """Вывод справки"""
    print(f"{COLORS['BOLD']}Apollo v{VERSION} - Мультиплатформенный лаунчер{COLORS['END']}")
    print()
    print(f"{COLORS['CYAN']}Использование:{COLORS['END']}")
    print("  apollo <команда> [аргументы]")
    print()
    print(f"{COLORS['CYAN']}Команды:{COLORS['END']}")
    print("  open <файл/имя>      Запустить приложение")
    print("  add <файл> [--name]  Добавить новое приложение")
    print("  list                 Список установленных приложений")
    print("  conf <имя>           Редактировать конфигурацию приложения")
    print("  remove <имя>         Удалить приложение")
    print("  info [имя]           Информация о системе или приложении")
    print("  clean                Очистка логов и временных файлов")
    print("  help                 Показать эту справку")
    print()
    print(f"{COLORS['CYAN']}Примеры:{COLORS['END']}")
    print("  apollo add program.exe --name MyApp")
    print("  apollo conf MyApp")
    print("  apollo open MyApp")
    print("  apollo open /path/to/game.exe")
    print()

def main() -> None:
    """Главная функция"""
    ensure_dirs()
    
    if len(sys.argv) < 2:
        print_help()
        return
    
    command = sys.argv[1]
    
    try:
        if command == "open":
            if len(sys.argv) < 3:
                msg("ERROR", "Укажите файл или имя приложения")
                print_help()
            else:
                cmd_open(sys.argv[2])
        
        elif command == "add":
            if len(sys.argv) < 3:
                msg("ERROR", "Укажите путь к файлу")
                print_help()
            else:
                name = None
                if "--name" in sys.argv:
                    name_index = sys.argv.index("--name") + 1
                    if name_index < len(sys.argv):
                        name = sys.argv[name_index]
                cmd_add(sys.argv[2], name)
        
        elif command == "list":
            cmd_list()
        
        elif command == "conf":
            if len(sys.argv) < 3:
                msg("ERROR", "Укажите имя приложения")
                cmd_list()
            else:
                cmd_conf(sys.argv[2])
        
        elif command == "remove":
            if len(sys.argv) < 3:
                msg("ERROR", "Укажите имя приложения")
                cmd_list()
            else:
                cmd_remove(sys.argv[2])
        
        elif command == "info":
            cmd_info(sys.argv[2] if len(sys.argv) > 2 else None)
        
        elif command == "clean":
            cmd_clean()
        
        elif command in ["help", "--help", "-h"]:
            print_help()
        
        elif command in ["version", "--version", "-v"]:
            print(f"Apollo v{VERSION}")
        
        else:
            msg("ERROR", f"Неизвестная команда: {command}")
            print_help()
    
    except KeyboardInterrupt:
        msg("INFO", "Прервано пользователем")
        sys.exit(0)
    except Exception as e:
        msg("ERROR", f"Непредвиденная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
