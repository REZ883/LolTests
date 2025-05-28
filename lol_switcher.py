import json
import sys
import os
import time
import subprocess
import pyperclip
import threading
import urllib.parse
from collections import Counter
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import logging
import logging.handlers

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QScrollArea, QFrame, QProgressBar, QGridLayout, QLineEdit,
    QDialog, QMessageBox, QDialogButtonBox, QSizePolicy, QStyle, QComboBox
)
from PySide6.QtGui import QPixmap, QIcon, QFont, QImage, QPainter, QColor, QBrush, QPen
from PySide6.QtCore import Qt, QThread, Signal, Slot, QSize, QTimer, QRect

import pyautogui
from cryptography.fernet import Fernet
import cv2
import numpy as np
import psutil
import win32gui
import win32con
from PIL import Image

logger = logging.getLogger(__name__)

def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    log_file = resource_path("lol_switcher.log")
    
    file_handler = logging.handlers.TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO) 

    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO) 
    logger.info("Logging setup complete.")


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def charger_cle():
    cle_path = resource_path("cle_secrete.key")
    try:
        with open(cle_path, "rb") as f: return f.read()
    except FileNotFoundError:
        logger.info("Key file not found, generating a new one.")
        key = Fernet.generate_key()
        with open(cle_path, "wb") as f: f.write(key)
        return key
    except Exception as e:
        logger.error(f"Error loading or generating key: {e}")
        return Fernet.generate_key() 


DDRAGON_BASE_URL = "https://ddragon.leagueoflegends.com"
CACHE_DIR = resource_path("ddragon_cache")
API_CACHE_FILE = resource_path("api_cache.json")
CACHE_TTL_LIST = 3600 
CACHE_TTL_DETAIL = 1800 
MATCH_HISTORY_COUNT = 5 

def get_latest_version():
    try:
        r = requests.get(f"{DDRAGON_BASE_URL}/api/versions.json", timeout=5)
        r.raise_for_status()
        return r.json()[0]
    except Exception as e:
        logger.error(f"Error fetching DDragon version: {e}")
        return None

def download_json(url, save_path):
    try:
        logger.info(f"DDragon Download: {url}")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f: json.dump(r.json(), f)
        logger.info(f"Saved: {save_path}")
        return True
    except Exception as e:
        logger.error(f"Failed DDragon Download {url}: {e}")
        return False

def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON {path}: {e}")
        return None

key = charger_cle()
cipher = Fernet(key)

def sauvegarder_comptes(comptes):
    json_path = resource_path("comptes_lol.json")
    try:
        temp_comptes = {}
        for k, v in comptes.items():
            temp_comptes[k] = v.copy()
            if 'tag_line' in temp_comptes[k] and isinstance(temp_comptes[k]['tag_line'], str):
                temp_comptes[k]['tag_line'] = temp_comptes[k]['tag_line'].strip().lstrip('#')

        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(temp_comptes, f, indent=4, ensure_ascii=False)
        logger.info(f"Accounts saved to {json_path}")
    except Exception as e:
        logger.error(f"Error saving accounts: {e}", exc_info=True)


def charger_comptes():
    json_path = resource_path("comptes_lol.json")
    default = {"Exemple": {"game_name": "NomJeu", "tag_line": "TAG", "username": "Login", "password": cipher.encrypt(b"MotDePasse").decode(), "region": "EUW1"}}
    try:
        needs_save = False
        if not os.path.exists(json_path): raise FileNotFoundError
        with open(json_path, "r", encoding='utf-8') as f: comptes = json.load(f)
        if not isinstance(comptes, dict): raise json.JSONDecodeError("Invalid format", "", 0)
        
        comptes_copy = dict(comptes) 
        for account_key, info in comptes_copy.items():
            if not isinstance(info, dict):
                 logger.warning(f"Invalid entry format for {account_key}, removing.")
                 del comptes[account_key]
                 needs_save = True
                 continue

            if 'region' not in info or not info['region']: info['region'] = "EUW1"; needs_save = True
            if 'username' not in info: info['username'] = info.get('game_name', ''); needs_save = True
            if 'game_name' not in info: info['game_name'] = ""; needs_save = True
            
            if 'password' not in info or not isinstance(info.get('password'), str) or not info.get('password'):
                logger.warning(f"Password missing/invalid for {account_key}, resetting to default 'MotDePasse'.")
                info['password'] = cipher.encrypt(b"MotDePasse").decode()
                needs_save = True

            tag = info.get('tag_line', '')
            if not isinstance(tag, str):
                tag = ''
                info['tag_line'] = ''
                needs_save = True
            
            cleaned_tag = tag.strip().lstrip('#')
            if tag != cleaned_tag or not tag : 
                info['tag_line'] = cleaned_tag
                needs_save = True
        
        if needs_save: sauvegarder_comptes(comptes)
        return comptes
    except FileNotFoundError:
        logger.info(f"File '{json_path}' not found, creating default.")
        sauvegarder_comptes(default)
        return default.copy()
    except json.JSONDecodeError as e:
         logger.error(f"JSON error in '{json_path}': {e}. Creating default.")
         sauvegarder_comptes(default)
         return default.copy()
    except Exception as e:
        logger.error(f"Error loading accounts: {e}", exc_info=True)
        return default.copy()


def activer_fenetre_riot():
    hwnd = win32gui.FindWindow(None, "Riot Client")
    if hwnd:
        try:
            is_minimized = win32gui.IsIconic(hwnd)
            if is_minimized: win32gui.ShowWindow(hwnd, win32con.SW_RESTORE); time.sleep(0.3)
            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception as e_fg: 
                logger.warning(f"SetForegroundWindow failed ({e_fg}), trying SW_SHOW")
                win32gui.ShowWindow(hwnd, win32con.SW_SHOW) 
            time.sleep(0.1) 
            if win32gui.GetForegroundWindow() == hwnd:
                logger.info("Riot window activated.")
                return hwnd
            else:
                logger.warning("Riot window found but not in foreground.")
                return hwnd 
        except Exception as e:
            logger.error(f"Win32 activation error: {e}")
            return None
    else:
        logger.info("Riot Client window not found.")
        return None

def est_client_riot_actif():
    for proc in psutil.process_iter(['name']):
        try:
            p_name = proc.info['name']
            if "RiotClientServices" in p_name or "RiotClientUx.exe" in p_name or "Riot Client.exe" in p_name:
                 return True
        except Exception: 
            pass
    return False

def attendre_processus(process_name_part, timeout=20):
    start = time.time()
    logger.info(f"Waiting for process containing '{process_name_part}' (max {timeout}s)...")
    proc_name_lower = process_name_part.lower()
    while time.time() - start < timeout:
        for proc in psutil.process_iter(['name']):
            try:
                if proc_name_lower in proc.info['name'].lower():
                    logger.info(f"Process '{proc.info['name']}' found.")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(1)
    logger.warning(f"Timeout: Process '{process_name_part}' not found.")
    return False


class ListFetchThread(QThread):
    result_ready = Signal(dict)
    list_progress = Signal(int, int)

    def __init__(self, comptes_to_fetch, previous_selection, parent_app):
        super().__init__()
        self.comptes_to_fetch = comptes_to_fetch
        self.previous_selection = previous_selection
        self.parent_app = parent_app
        self.setObjectName("ListFetchThread")


    def run(self):
        results_data = {}
        tasks = {}
        accounts_to_fetch = []
        current_time = time.time()

        for key, info in self.comptes_to_fetch.items():
            cached_entry = self.parent_app.api_cache.get(key, {}).get("summoner_info")
            if cached_entry and (current_time - cached_entry.get("timestamp", 0)) < CACHE_TTL_LIST:
                 logger.info(f"Cache hit for summoner_info: {key}")
                 results_data[key] = {'summoner': cached_entry['data']}
            else:
                accounts_to_fetch.append((key, info))

        total_to_fetch = len(accounts_to_fetch)
        self.list_progress.emit(0, total_to_fetch)

        with ThreadPoolExecutor(max_workers=self.parent_app.api_executor._max_workers, thread_name_prefix='ListFetchInternal') as list_internal_executor:
            for key, info in accounts_to_fetch:
                if not self.parent_app.app_running: break
                gn = info.get('game_name')
                tl = info.get('tag_line','').strip().lstrip('#')
                rg = info.get('region','EUW1')
                if gn and tl:
                    try:
                        future = list_internal_executor.submit(self.parent_app.get_summoner_info_sync, gn, tl, rg)
                        tasks[future] = key
                    except RuntimeError as e: 
                        logger.error(f"RuntimeError submitting task for {key} in ListFetchThread: {e}")
                        results_data[key] = {'summoner': {'display': f"Erreur thread: {e}", 'error': True}}
                        break 
                else:
                    s_data = {'display':"(Infos manquantes)", 'error':True, 'level':'N/A', 'tier':'UNRANKED', 'rank_div':'', 'lp':0, 'ranked_stats':None}
                    results_data[key] = {'summoner': s_data}

            completed_count = 0
            for future in as_completed(tasks):
                if not self.parent_app.app_running: break
                key = tasks[future]
                try:
                    s_data = future.result()
                    results_data[key] = {'summoner': s_data}
                    if s_data and not s_data.get('error'):
                        self.parent_app.update_api_cache(key, "summoner_info", s_data)
                except Exception as exc:
                    logger.error(f"Error fetching summoner info for {key}: {exc}", exc_info=True)
                    results_data[key] = {'summoner': {'display': f"Erreur fetch: {exc}", 'error': True}}
                finally:
                    completed_count += 1
                    self.list_progress.emit(completed_count, total_to_fetch)

        if self.parent_app.app_running: 
             self.result_ready.emit({'type':'list_refresh', 'data': results_data, 'previous_selection': self.previous_selection})

class DetailFetchThread(QThread):
    result_ready = Signal(dict)

    def __init__(self, account_key, puuid, region, parent_app):
        super().__init__()
        self.account_key = account_key
        self.puuid = puuid
        self.region = region
        self.parent_app = parent_app
        self.setObjectName("DetailFetchThread")

    def run(self):
        if not self.parent_app.app_running or not self.puuid: return
        logger.info(f"Thread-Detail: Fetching Details for {self.account_key} (PUUID: {self.puuid[:8]}..., Region: {self.region})")
        mastery_data = None
        match_stats = None
        current_time = time.time()
        needs_mastery_fetch = True
        needs_stats_fetch = True

        cached_mastery = self.parent_app.api_cache.get(self.account_key, {}).get("mastery")
        if cached_mastery and (current_time - cached_mastery.get("timestamp", 0)) < CACHE_TTL_DETAIL:
            logger.info(f"Cache hit for mastery: {self.account_key}")
            mastery_data = cached_mastery['data']
            needs_mastery_fetch = False

        cached_stats = self.parent_app.api_cache.get(self.account_key, {}).get("match_stats")
        if cached_stats and (current_time - cached_stats.get("timestamp", 0)) < CACHE_TTL_DETAIL:
            logger.info(f"Cache hit for match_stats: {self.account_key}")
            match_stats = cached_stats['data']
            needs_stats_fetch = False

        if needs_mastery_fetch or needs_stats_fetch:
            try:
                if needs_mastery_fetch:
                    if not self.parent_app.app_running: return
                    mastery_data = self.parent_app.get_champion_mastery_sync(self.puuid, self.region)
                    time.sleep(0.05) 
                    if mastery_data is not None:
                         self.parent_app.update_api_cache(self.account_key, "mastery", mastery_data)

                if needs_stats_fetch and self.parent_app.app_running:
                     endpoints = self.parent_app.get_region_endpoints(self.region)
                     match_stats = self.parent_app.analyze_match_history_sync(self.puuid, endpoints)
                     if match_stats is not None:
                         self.parent_app.update_api_cache(self.account_key, "match_stats", match_stats)

            except RuntimeError as e: 
                logger.error(f"RuntimeError in DetailFetchThread for {self.account_key}: {e}")
            except Exception as e:
                logger.error(f"Error in DetailFetchThread for {self.account_key}: {e}", exc_info=True)

        if self.parent_app.app_running:
            logger.info(f"Thread-Detail: Queuing details for {self.account_key}")
            self.result_ready.emit({'type':'details', 'key':self.account_key, 'data':{'mastery':mastery_data, 'stats':match_stats}})


class LaunchThread(QThread):
    update_status_signal = Signal(str, str, bool)
    show_message_signal = Signal(str, str)

    def __init__(self, username, password, parent_app):
        super().__init__()
        self.username = username
        self.password = password
        self.parent_app = parent_app
        self.setObjectName("LaunchThread")

    def run(self):
        try:
            if est_client_riot_actif():
                self.update_status_signal.emit("Fermeture client existant...", "orange", False)
                logger.info("Riot/LoL client detected, attempting to close...")
                if not self.parent_app.fermer_client_lol_sync():
                    logger.warning("Failed to fully close existing client.")


            logger.info(f"Launching and logging in for {self.username}...")
            login_success = self.parent_app.lancer_client_lol_sync(self.username, self.password)

            if login_success:
                 logger.info(f"Login successful (or at least attempted) for {self.username}.")
            else:
                logger.warning(f"Launch/login failed for {self.username}.")

        except Exception as e:
              logger.error(f"Major error in login thread: {e}", exc_info=True)
              self.update_status_signal.emit("Erreur connexion thread.", "red", False)


class LolSwitcherApp(QMainWindow):
    list_data_received = Signal(dict)
    detail_data_received = Signal(dict)

    def __init__(self):
        super().__init__()
        self.app_running = True
        self.update_thread = None
        self.detail_fetch_thread = None
        self.launch_thread = None
        self.ddragon_version = None
        self.champion_id_map = {}
        self.rank_icon_cache = {}

        self.api_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='MainAPIExecutor')
        
        self.api_cache = self._load_api_cache()
        self.http_session = requests.Session()

        self._setup_ddragon_async()

        self.comptes = charger_comptes()
        self.selected_account_key = None
        self.detailed_stats_cache = {} 
        self.account_widgets = {}

        self.api_key = "RGAPI-d2a25856-b461-48fb-a0e3-101cf599efd6" 
        self.account_url_base = "https://{region_routing}.api.riotgames.com"
        self.summoner_url_base = "https://{region_platform}.api.riotgames.com"
        self.match_url_base = "https://{region_routing}.api.riotgames.com"
        self.mastery_url_base = "https://{region_platform}.api.riotgames.com"
        self.region_map = {"EUW1": {"routing": "europe", "platform": "euw1"}, "EUN1": {"routing": "europe", "platform": "eun1"},
                           "NA1": {"routing": "americas", "platform": "na1"}, "KR": {"routing": "asia", "platform": "kr"},
                           "BR1": {"routing": "americas", "platform": "br1"}, "LA1": {"routing": "americas", "platform": "la1"},
                           "LA2": {"routing": "americas", "platform": "la2"}, "OC1": {"routing": "sea", "platform": "oc1"},
                           "TR1": {"routing": "europe", "platform": "tr1"}, "RU": {"routing": "europe", "platform": "ru"},
                           "JP1": {"routing": "asia", "platform": "jp1"},}
        self.headers = {"X-Riot-Token": self.api_key.strip()}
        self.http_session.headers.update(self.headers)


        self.setWindowTitle("LoL Account Switcher (PySide6)")
        try:
            self.setWindowIcon(QIcon(resource_path("app_icon.ico")))
        except Exception as e:
            logger.error(f"Error setting window icon: {e}")

        self.setGeometry(100, 100, 800, 750)
        self.setMinimumSize(700, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        self._create_widgets()
        self._apply_stylesheet()

        self.list_data_received.connect(self.handle_api_results)
        self.detail_data_received.connect(self.handle_api_results)
        
        self._refresh_ui_list_sync()


    def _load_api_cache(self):
        if os.path.exists(API_CACHE_FILE):
            try:
                with open(API_CACHE_FILE, 'r', encoding='utf-8') as f:
                    logger.info("Loading API cache...")
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading API cache: {e}")
        return {}

    def _save_api_cache(self):
        try:
            with open(API_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.api_cache, f, indent=4)
            logger.info("API cache saved.")
        except Exception as e:
            logger.error(f"Error saving API cache: {e}")

    def update_api_cache(self, account_key, data_key, data):
         if account_key not in self.api_cache:
             self.api_cache[account_key] = {}
         self.api_cache[account_key][data_key] = {
             "data": data,
             "timestamp": time.time()
         }


    def _setup_ddragon_async(self):
        dd_thread = threading.Thread(target=self._setup_ddragon_worker, daemon=True)
        dd_thread.start()

    def _setup_ddragon_worker(self):
        logger.info("Configuring DDragon...")
        self.ddragon_version = get_latest_version()
        if not self.ddragon_version:
            logger.error("Failed to get DDragon version.")
            return
        logger.info(f"DDragon Version: {self.ddragon_version}")
        champ_path = os.path.join(CACHE_DIR, self.ddragon_version, "champion.json")
        champ_data = load_json(champ_path) if os.path.exists(champ_path) else None

        if not champ_data:
            logger.info("Champion cache missing, downloading...")
            locale = "fr_FR" 
            url = f"{DDRAGON_BASE_URL}/cdn/{self.ddragon_version}/data/{locale}/champion.json"
            if download_json(url, champ_path):
                champ_data = load_json(champ_path)
            else:
                logger.error(f"Failed to download champion data for version {self.ddragon_version}.")
                return

        if champ_data and 'data' in champ_data:
            try:
                temp_map = {c['key']: c['name'] for c in champ_data['data'].values() if 'key' in c and 'name' in c}
                self.champion_id_map = temp_map
                logger.info(f"DDragon: {len(self.champion_id_map)} champions loaded.")
            except Exception as e:
                logger.error(f"Error mapping champion data: {e}")
        else:
            logger.error("Error: Invalid champion.json format.")

    def _create_widgets(self):
        header_layout = QHBoxLayout()
        try:
            logo_pixmap = QPixmap(resource_path("logo.png")).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label = QLabel()
            self.logo_label.setPixmap(logo_pixmap)
            header_layout.addWidget(self.logo_label)
        except Exception as e:
            logger.error(f"Error loading logo: {e}")
            header_layout.addWidget(QLabel("L?")) 

        title_status_layout = QVBoxLayout()
        self.title_label = QLabel("LoL Account Switcher")
        self.title_label.setObjectName("TitleLabel")
        title_status_layout.addWidget(self.title_label)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("Initialisation...")
        self.status_label.setObjectName("StatusLabel")
        status_layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("ProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setMaximumWidth(180)
        self.progress_bar.setTextVisible(False)
        status_layout.addWidget(self.progress_bar)
        status_layout.addStretch()
        title_status_layout.addLayout(status_layout)

        header_layout.addLayout(title_status_layout)
        header_layout.addStretch()

        self.refresh_button = QPushButton()
        self.refresh_button.setObjectName("RefreshButton")
        refresh_icon = self.style().standardIcon(QStyle.SP_BrowserReload)
        self.refresh_button.setIcon(refresh_icon)
        self.refresh_button.setIconSize(QSize(18,18))
        self.refresh_button.setFixedSize(QSize(36, 36))
        self.refresh_button.setToolTip("Rafraîchir la liste des comptes et les données (API)")
        self.refresh_button.clicked.connect(self.start_update_thread)
        header_layout.addWidget(self.refresh_button)
        self.main_layout.addLayout(header_layout)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setObjectName("ScrollArea")
        self.scroll_content_widget = QWidget()
        self.accounts_layout = QVBoxLayout(self.scroll_content_widget)
        self.accounts_layout.setAlignment(Qt.AlignTop)
        self.accounts_layout.setSpacing(8)
        self.accounts_layout.setContentsMargins(8, 8, 8, 8)
        self.scroll_area.setWidget(self.scroll_content_widget)
        self.main_layout.addWidget(self.scroll_area, 1)

        details_frame = QFrame()
        details_frame.setObjectName("DetailsFrame")
        details_frame.setFrameShape(QFrame.StyledPanel)
        details_layout = QHBoxLayout(details_frame)
        details_layout.setSpacing(20)

        stats_widget = QWidget()
        stats_widget.setObjectName("StatsWidget")
        stats_layout = QVBoxLayout(stats_widget)
        self.stats_title_label = QLabel(f"Stats ({MATCH_HISTORY_COUNT} Classées)") 
        self.stats_title_label.setObjectName("DetailsTitleLabel")
        self.stats_title_label.setAlignment(Qt.AlignCenter)
        self.stats_label = QLabel("...")
        self.stats_label.setObjectName("DetailsContentLabel")
        self.stats_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.stats_label.setWordWrap(True)
        stats_layout.addWidget(self.stats_title_label)
        stats_layout.addWidget(self.stats_label, 1)
        details_layout.addWidget(stats_widget)

        mastery_widget = QWidget()
        mastery_widget.setObjectName("MasteryWidget")
        mastery_layout_container = QVBoxLayout(mastery_widget)
        mastery_title = QLabel("Top 3 Maîtrise")
        mastery_title.setObjectName("DetailsTitleLabel")
        mastery_title.setAlignment(Qt.AlignCenter)
        self.mastery_label = QLabel("...")
        self.mastery_label.setObjectName("DetailsContentLabel")
        self.mastery_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.mastery_label.setWordWrap(True)
        mastery_layout_container.addWidget(mastery_title)
        mastery_layout_container.addWidget(self.mastery_label, 1)

        details_layout.addWidget(mastery_widget)
        self.main_layout.addWidget(details_frame)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        add_icon = self.style().standardIcon(QStyle.SP_FileDialogNewFolder)
        self.add_button = QPushButton()
        self.add_button.setIcon(add_icon); self.add_button.setIconSize(QSize(20,20)); self.add_button.setFixedSize(QSize(40, 40))
        self.add_button.setObjectName("ManagementButton"); self.add_button.setToolTip("Ajouter un compte")

        mod_icon = self.style().standardIcon(QStyle.SP_FileDialogDetailedView)
        self.mod_button = QPushButton()
        self.mod_button.setIcon(mod_icon); self.mod_button.setIconSize(QSize(20,20)); self.mod_button.setFixedSize(QSize(40, 40))
        self.mod_button.setObjectName("ManagementButton"); self.mod_button.setToolTip("Modifier le compte sélectionné")

        del_icon = self.style().standardIcon(QStyle.SP_TrashIcon)
        self.del_button = QPushButton()
        self.del_button.setIcon(del_icon); self.del_button.setIconSize(QSize(20,20)); self.del_button.setFixedSize(QSize(40, 40))
        self.del_button.setObjectName("ManagementButton"); self.del_button.setToolTip("Supprimer le compte sélectionné")

        quit_icon = self.style().standardIcon(QStyle.SP_DialogCloseButton)
        self.quit_button = QPushButton()
        self.quit_button.setIcon(quit_icon); self.quit_button.setIconSize(QSize(20,20)); self.quit_button.setFixedSize(QSize(40, 40))
        self.quit_button.setObjectName("ManagementButton"); self.quit_button.setToolTip("Quitter l'application")

        self.add_button.clicked.connect(self.ajouter_compte); self.mod_button.clicked.connect(self.modifier_compte)
        self.del_button.clicked.connect(self.supprimer_compte); self.quit_button.clicked.connect(self.close)

        button_layout.addWidget(self.add_button); button_layout.addWidget(self.mod_button); button_layout.addWidget(self.del_button)
        button_layout.addStretch(); button_layout.addWidget(self.quit_button)
        self.main_layout.addLayout(button_layout)

        launch_frame = QFrame(); launch_frame.setObjectName("LaunchFrame")
        launch_layout = QHBoxLayout(launch_frame)
        self.launch_button = QPushButton("Lancer Compte Sélectionné"); self.launch_button.setObjectName("LaunchButton")
        self.launch_button.setIconSize(QSize(24,24)); self.launch_button.clicked.connect(self.lancer_connexion_auto_selected)
        launch_layout.addStretch(); launch_layout.addWidget(self.launch_button); launch_layout.addStretch()
        self.main_layout.addWidget(launch_frame)

    def _apply_stylesheet(self):
        dark_bg = "#0A121A"; medium_bg = "#101822"; light_bg = "#1A2430"; text_color = "#E0E0E0"; text_color_muted = "#A0A0A0"
        accent1 = "#0AC8B9"; accent1_light = "#3EF0DE"; accent1_dark = "#08A090"; accent2 = "#C8AA6E"; accent2_light = "#E0C080"; accent2_dark = "#B0905A"
        border_color = "#2A3A5A"; selection_bg = "#2A3A5A"; error_color = "#E84057"; warning_color = "#FFA500"
        self.setStyleSheet(f"""
            LolSwitcherApp, QWidget {{ background-color: {dark_bg}; color: {text_color}; font-family: Segoe UI, Helvetica, Arial; font-size: 10pt; }}
            QFrame#DetailsFrame, QFrame#LaunchFrame, QWidget#AccountWidget, QDialog {{ background-color: {medium_bg}; border: 1px solid {border_color}; border-radius: 6px; }}
            QWidget#StatsWidget, QWidget#MasteryWidget {{ background-color: transparent; border: none; }}
            QLabel#TitleLabel {{ color: {accent2}; font-size: 22pt; font-weight: bold; padding-bottom: 5px; }}
            QLabel#StatusLabel {{ color: {warning_color}; font-size: 9pt; background-color: transparent; }}
            QLabel#StatusLabel[status="ready"] {{ color: {accent1}; }} QLabel#StatusLabel[status="error"] {{ color: {error_color}; }}
            QLabel#DetailsTitleLabel {{ color: {accent1}; font-weight: bold; font-size: 12pt; padding-bottom: 5px; margin-bottom: 8px; background-color: transparent; border: none; }}
            QLabel#DetailsContentLabel {{ color: {text_color}; font-size: 10pt; background-color: transparent; line-height: 1.4; }}
            QLabel#AccountNameLabel {{ font-weight: bold; font-size: 14pt; color: {accent2}; background-color: transparent; margin-bottom: 2px; }}
            QLabel#AccountRankLabel {{ font-size: 9pt; color: {text_color_muted}; background-color: transparent; }}
            QLabel#AccountRankLabel[rankType="bold"] {{ color: {text_color}; font-weight: bold; }}
            QLabel#AccountLevelLabel {{ font-size: 9pt; color: {text_color_muted}; background-color: transparent; margin-top: 2px; }}
            QLabel#MasteryNameLevelLabel {{ font-size: 10pt; font-weight: bold; color: {text_color}; background-color: transparent; }}
            QLabel#MasteryPointsLabel {{ font-size: 9pt; color: {text_color_muted}; background-color: transparent; }}
            QLabel#MasteryIconLabel {{ background-color: transparent; }}
            QPushButton {{ background-color: {accent1}; color: {dark_bg}; border: none; padding: 8px 12px; font-weight: bold; border-radius: 5px; min-height: 24px; }}
            QPushButton:hover {{ background-color: {accent1_light}; }} QPushButton:pressed {{ background-color: {accent1_dark}; }}
            QPushButton:disabled {{ background-color: #404040; color: #808080; }}
            QPushButton#LaunchButton {{ background-color: {accent2}; color: {dark_bg}; font-size: 15pt; padding: 12px 20px; min-height: 35px; }}
            QPushButton#LaunchButton:hover {{ background-color: {accent2_light}; }} QPushButton#LaunchButton:pressed {{ background-color: {accent2_dark}; }}
            QPushButton#RefreshButton, QPushButton#ManagementButton {{ background-color: {light_bg}; border: 1px solid {border_color}; padding: 5px; min-height: 26px; min-width: 26px; border-radius: 18px; color: {text_color}; }}
            QPushButton#RefreshButton:hover, QPushButton#ManagementButton:hover {{ background-color: {selection_bg}; border: 1px solid {accent1}; }}
            QPushButton#RefreshButton:pressed, QPushButton#ManagementButton:pressed {{ background-color: {dark_bg}; }}
            QScrollArea#ScrollArea {{ border: 1px solid {border_color}; background-color: {medium_bg}; border-radius: 6px; }}
            QScrollBar:vertical {{ border: none; background: {medium_bg}; width: 8px; margin: 0px 0px 0px 0px; border-radius: 4px; }}
            QScrollBar::handle:vertical {{ background: {light_bg}; min-height: 25px; border-radius: 4px; }}
            QScrollBar::handle:vertical:hover {{ background: {accent1}; }} QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; width: 0px; }}
            QProgressBar#ProgressBar {{ border: 1px solid {border_color}; border-radius: 6px; text-align: center; background-color: {light_bg}; height: 10px; }}
            QProgressBar::chunk {{ background-color: {accent1}; border-radius: 5px; }}
            QLineEdit {{ background-color: {light_bg}; color: {text_color}; border: 1px solid {border_color}; border-radius: 4px; padding: 6px; font-size: 10pt; }}
            QComboBox {{ background-color: {light_bg}; color: {text_color}; border: 1px solid {border_color}; border-radius: 4px; padding: 6px; font-size: 10pt; min-height: 1.5em; }}
            QComboBox QAbstractItemView {{ border: 1px solid {border_color}; background-color: {light_bg}; color: {text_color}; selection-background-color: {accent1}; }}
            QMessageBox, QDialog {{ background-color: {medium_bg}; color: {text_color}; font-size: 10pt; }}
            QDialog QLineEdit, QDialog QComboBox {{ background-color: {light_bg}; color: {text_color}; border: 1px solid {border_color}; }}
            QDialog QLabel {{ background-color: transparent; }}
            QDialog QPushButton {{ background-color: {accent1}; color: {dark_bg}; min-width: 80px; }}
            QDialog QPushButton:hover {{ background-color: {accent1_light}; }} QDialog QPushButton:pressed {{ background-color: {accent1_dark}; }}
            QWidget#AccountWidget {{ padding: 12px; border-radius: 6px; border: 1px solid {medium_bg}; }}
            QWidget#AccountWidget:hover {{ background-color: {light_bg}; border: 1px solid {border_color}; }}
            QWidget#AccountWidget[selected="true"] {{ background-color: {selection_bg}; border: 1px solid {accent1}; }}
        """)

    @Slot(str, str, bool)
    def update_status(self, message, color_name_or_hex, show_progress):
        if not self.app_running: return
        status_state = "normal"
        color_map = {"orange": "#FFA500", "green": "#0AC8B9", "red": "#E84057", "blue": "#5383E8", "gray": "#808080", "yellow": "#FFC107"}
        final_color = color_map.get(color_name_or_hex.lower(), color_name_or_hex)
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {final_color}; background-color: transparent;")
        if color_name_or_hex.lower() == "green": status_state = "ready"
        elif color_name_or_hex.lower() == "red": status_state = "error"
        self.status_label.setProperty("status", status_state)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        self.progress_bar.setVisible(show_progress)
        if not show_progress: 
            self.progress_bar.setRange(0,100)
            self.progress_bar.setValue(0)
        else: 
            if message.startswith("Chargement API"):
                  self.progress_bar.setRange(0, 100) 
                  self.progress_bar.setValue(0) 
            else:
                  self.progress_bar.setRange(0,0)


    @Slot(int, int)
    def update_list_progress(self, current, total):
        if total > 0: 
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(int((current / total) * 100))
            self.progress_bar.setVisible(True)
        else: 
            self.progress_bar.setVisible(False)

    @Slot(str, str)
    def show_message_box(self, title, message):
        if "erreur" in title.lower(): 
            QMessageBox.critical(self, title, message)
        elif "avertissement" in title.lower(): 
            QMessageBox.warning(self, title, message)
        else: 
            QMessageBox.information(self, title, message)

    def trouver_image(self, image_name_in_subfolder, confidence=0.7, region=None):
        image_subpath = os.path.join("CV_Images", image_name_in_subfolder)
        image_path = resource_path(image_subpath)
        try:
            template = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
            assert template is not None, f"Image vide/introuvable: {image_path}"
        except Exception as e: 
            logger.error(f"Error loading image {image_path}: {e}")
            return None
        try:
            ss_pil = pyautogui.screenshot(region=region)
            ss_cv = cv2.cvtColor(np.array(ss_pil), cv2.COLOR_RGB2GRAY)
            res = cv2.matchTemplate(ss_cv, template, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, max_loc = cv2.minMaxLoc(res)
            if max_val >= confidence: 
                h, w = template.shape[:2]
                cx = (region[0] if region else 0) + max_loc[0] + w // 2
                cy = (region[1] if region else 0) + max_loc[1] + h // 2
                return (cx, cy)
        except Exception as e: 
            logger.error(f"Error in find_image for {image_name_in_subfolder}: {e}", exc_info=False)
            return None
        return None

    def attendre_image(self, image_name, timeout=20, confidence=0.7, region=None):
        start_time_wait = time.time() # Renamed to avoid conflict with outer scope 'start'
        region_txt = f" in region {region}" if region else ""
        logger.info(f"Waiting for {image_name}{region_txt} (max {timeout}s)...")
        while time.time() - start_time_wait < timeout:
            if hasattr(self, 'app_running') and not self.app_running: 
                return None
            coords = self.trouver_image(image_name, confidence=confidence, region=region)
            if coords: 
                logger.info(f"{image_name} found @ {coords}.")
                return coords
            time.sleep(0.25) # Standard sleep interval between checks
        logger.warning(f"Timeout: {image_name} not found.")
        return None

    def cliquer_coord(self, coords, image_name_debug="coord"):
        if coords: 
            cx, cy = coords
            time.sleep(0.1)
            pyautogui.moveTo(cx, cy, duration=0.1)
            pyautogui.click(cx, cy)
            logger.info(f"Clicked {image_name_debug} @({cx},{cy})")
            time.sleep(0.5)
            return True
        else: 
            logger.warning(f"Cannot click, invalid coordinates for: {image_name_debug}")
            return False

    def trouver_et_cliquer(self, image_name, timeout=10, confidence=0.7, region=None):
        coords = self.attendre_image(image_name, timeout=timeout, confidence=confidence, region=region)
        return self.cliquer_coord(coords, image_name_debug=image_name)

    def _create_single_account_widget(self, key, account_data, summoner_info):
        acc_widget = QWidget()
        acc_widget.setObjectName("AccountWidget")
        acc_widget.setProperty("selected", False)
        acc_widget.setAutoFillBackground(True)
        acc_layout = QVBoxLayout(acc_widget)
        acc_layout.setContentsMargins(12, 12, 12, 12)
        acc_layout.setSpacing(4)
        name_label = QLabel(key)
        name_label.setObjectName("AccountNameLabel")
        acc_layout.addWidget(name_label)
        rank_widget = QWidget()
        rank_layout = QHBoxLayout(rank_widget)
        rank_layout.setContentsMargins(0,0,0,0)
        rank_layout.setAlignment(Qt.AlignLeft)
        rank_layout.setSpacing(5)
        tier = summoner_info.get('tier','?')
        r_div = summoner_info.get('rank_div','')
        lp = summoner_info.get('lp',0)
        r_stats = summoner_info.get('ranked_stats')
        icon_label = QLabel()
        icon_label.setFixedSize(24, 24)
        icon_file = f"Season_2023_-_{str(tier).lower()}.png"
        icon_full_path = resource_path(os.path.join("ranked_emblems", icon_file))
        pixmap = self.rank_icon_cache.get(icon_full_path)
        if tier not in ['?', 'UNRANKED'] and not pixmap:
            if os.path.exists(icon_full_path):
                try: 
                    pixmap = QPixmap(icon_full_path).scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    self.rank_icon_cache[icon_full_path] = pixmap
                except Exception as e: 
                    logger.error(f"Error loading rank icon Qt {icon_full_path}: {e}")
                    pixmap = None
            else: 
                pixmap = None
                logger.warning(f"Rank icon missing: {icon_full_path}")
        if pixmap: 
            icon_label.setPixmap(pixmap)
        else: 
            icon_label.setText("") 
        rank_layout.addWidget(icon_label)
        r_txt = f"{str(tier).capitalize()} {r_div}" if tier != 'UNRANKED' and tier != '?' else ("Unranked" if tier == 'UNRANKED' else "?")
        lp_txt = f" {lp} LP" if tier != 'UNRANKED' and tier != '?' else ""
        rank_label = QLabel(r_txt)
        rank_label.setObjectName("AccountRankLabel")
        rank_label.setProperty("rankType", "bold")
        lp_label = QLabel(lp_txt)
        lp_label.setObjectName("AccountRankLabel")
        rank_layout.addWidget(rank_label)
        rank_layout.addWidget(lp_label)
        if r_stats and r_stats['total'] > 0: 
            wr_txt = f" | {r_stats['wins']}V-{r_stats['losses']}D ({r_stats['wr']:.0f}%)"
            wr_label = QLabel(wr_txt)
            wr_label.setObjectName("AccountInfoLabel")
            rank_layout.addWidget(wr_label)
        rank_layout.addStretch()
        acc_layout.addWidget(rank_widget)
        lvl = summoner_info.get('level','N/A')
        lvl_label = QLabel(f"Niveau {lvl}")
        lvl_label.setObjectName("AccountLevelLabel")
        acc_layout.addWidget(lvl_label)
        acc_widget.mousePressEvent = lambda event, k=key: self._on_account_clicked(k)
        acc_widget.mouseDoubleClickEvent = lambda event, k=key: self.lancer_connexion_auto(k)
        return acc_widget

    def start_update_thread(self):
        if self.update_thread and self.update_thread.isRunning(): 
            logger.info("Update already in progress.")
            self.update_status("MàJ en cours...", "orange", True)
            return
        self.update_status("Chargement API (Liste)...", "orange", True)
        self.progress_bar.setRange(0,0)
        while self.accounts_layout.count(): 
            item = self.accounts_layout.takeAt(0)
            widget = item.widget()
            if widget: 
                widget.deleteLater()
        self.account_widgets = {}
        cur_sel = self.selected_account_key
        self.selected_account_key = None 
        self.stats_label.setText("Chargement...")
        self.mastery_label.setText("Chargement maîtrise...")
        comptes_copy = self.comptes.copy()
        self.update_thread = ListFetchThread(comptes_copy, cur_sel, self)
        self.update_thread.result_ready.connect(self.handle_api_results)
        self.update_thread.list_progress.connect(self.update_list_progress)
        self.update_thread.finished.connect(self.on_list_fetch_finished)
        self.update_thread.start()

    def _refresh_ui_list_sync(self):
        logger.info("Synchronous UI list refresh...")
        self.update_status("Mise à jour liste...", "orange", False)
        while self.accounts_layout.count(): 
            item = self.accounts_layout.takeAt(0)
            widget = item.widget()
            if widget: 
                widget.deleteLater()
        self.account_widgets = {}
        current_time = time.time()
        sorted_keys = sorted(list(self.comptes.keys()))
        first_key = None
        if not sorted_keys: 
            self.stats_label.setText("Aucun compte.")
            self.mastery_label.setText("")
            self.selected_account_key = None
            self.update_status("Prêt", "green", False)
            return
        for key in sorted_keys:
            if not first_key: 
                first_key = key
            account_data = self.comptes[key]
            cached_entry = self.api_cache.get(key, {}).get("summoner_info")
            if cached_entry and (current_time - cached_entry.get("timestamp", 0)) < CACHE_TTL_LIST: 
                s_info_data = cached_entry['data']
            else: 
                s_info_data = {'display': "(Données API non chargées/obsolètes)", 'error': True, 'level': 'N/A', 'tier': '?', 'rank_div': '', 'lp': 0, 'ranked_stats': None, 'puuid': None}
            if key not in self.detailed_stats_cache: 
                self.detailed_stats_cache[key] = {}
            self.detailed_stats_cache[key]['summoner'] = s_info_data
            acc_widget = self._create_single_account_widget(key, account_data, s_info_data)
            self.accounts_layout.addWidget(acc_widget)
            self.account_widgets[key] = acc_widget
        
        if self.selected_account_key not in self.account_widgets:
             self.selected_account_key = first_key if first_key else None

        if self.selected_account_key:
            QTimer.singleShot(10, lambda k=self.selected_account_key: self._select_account_ui(k))
        else: 
            self.stats_label.setText("Aucun compte.")
            self.mastery_label.setText("")
            self.selected_account_key = None 

        self.update_status("Liste rechargée.", "green", False)


    def on_list_fetch_finished(self): 
        self.update_status("Prêt", "green", False)
        self.progress_bar.setVisible(False)

    @Slot(dict)
    def handle_api_results(self, result):
         msg_type = result.get('type')
         if msg_type == 'list_refresh': 
             self._update_ui_list_refresh(result['data'], result.get('previous_selection'))
         elif msg_type == 'details': 
             self._update_ui_details(result['key'], result['data'])

    def get_region_endpoints(self, r_id):
        r_id_up = str(r_id).upper()
        r_data = self.region_map.get(r_id_up)
        if not r_data: 
            logger.warning(f"Region {r_id_up} unknown, defaulting to EUW1.")
            r_data = self.region_map["EUW1"]
        return {"account": self.account_url_base.format(region_routing=r_data["routing"]), "summoner": self.summoner_url_base.format(region_platform=r_data["platform"]),
                "match": self.match_url_base.format(region_routing=r_data["routing"]), "mastery": self.mastery_url_base.format(region_platform=r_data["platform"]),}

    def get_summoner_info_sync(self, game_name, tag_line, region_platform_id):
        ep=self.get_region_endpoints(region_platform_id)
        puuid=None; level="N/A"; tier="UNRANKED"; rank_div=""; lp=0; r_wins=0; r_losses=0; r_tot=0; r_wr=0.0
        res={'error': False}
        try:
            cl_tag=tag_line.strip().lstrip('#')
            assert cl_tag, "Tag Line cannot be empty"
            enc_gn=urllib.parse.quote(game_name)
            enc_tl=urllib.parse.quote(cl_tag)
            acc_ep=f"{ep['account']}/riot/account/v1/accounts/by-riot-id/{enc_gn}/{enc_tl}"
            acc_r=self.http_session.get(acc_ep, timeout=10);
            if acc_r.status_code==404: 
                logger.warning(f"API 404 (Account): Riot ID {game_name}#{cl_tag} not found.")
                return {'display':f"ID Riot introuvable.",'error':True}
            acc_r.raise_for_status()
            acc_data=acc_r.json()
            puuid=acc_data.get("puuid")
            if puuid: 
                res['puuid'] = puuid
            else: 
                logger.error(f"PUUID not found in response for {game_name}#{cl_tag}")
                return {'display': "PUUID introuvable.",'error': True}
            summ_ep=f"{ep['summoner']}/lol/summoner/v4/summoners/by-puuid/{puuid}"
            summ_r=self.http_session.get(summ_ep, timeout=10)
            summ_r.raise_for_status()
            summ_data=summ_r.json()
            summ_id=summ_data.get("id")
            level=summ_data.get('summonerLevel','N/A')
            res['level']=level;
            if not summ_id: 
                logger.error(f"Summoner ID not found for PUUID {puuid[:8]}...")
                return {'display':f"Niv. {level} | ID Summ introuvable.",'error':True, **res}
            lg_ep=f"{ep['summoner']}/lol/league/v4/entries/by-summoner/{summ_id}"
            lg_r=self.http_session.get(lg_ep, timeout=10)
            lg_r.raise_for_status()
            lg_info=lg_r.json()
            for entry in lg_info:
                if entry.get('queueType')=="RANKED_SOLO_5x5":
                    tier=entry.get('tier','UNRANKED')
                    rank_div=entry.get('rank','')
                    lp=entry.get('leaguePoints',0)
                    r_wins=entry.get('wins',0)
                    r_losses=entry.get('losses',0)
                    r_tot=r_wins+r_losses
                    r_wr=(r_wins/r_tot*100) if r_tot>0 else 0.0
                    break
            res['tier']=tier
            res['rank_div']=rank_div
            res['lp']=lp
            res['ranked_stats']={'wins':r_wins,'losses':r_losses,'total':r_tot,'wr':r_wr}
            res['stats']=None 
            return res
        except AssertionError as e: 
            logger.error(f"Assertion error for {game_name}#{tag_line}: {e}")
            res['display']=f"Erreur: {e}"; res['error']=True; return res
        except requests.exceptions.HTTPError as e:
            sc=e.response.status_code if e.response else 'N/A'
            url=e.request.url if e.request else 'N/A'
            api_err=f"API {sc}"
            if sc==429: 
                api_err="Limite API atteinte"
                logger.warning(f"Rate limit hit for {game_name}#{cl_tag} on {url}")
            elif sc==404: 
                api_err="Non trouvé (Summ/League?)"
            elif sc==403: 
                api_err="Clé API invalide/expirée (403)"
                logger.critical(f"CRITICAL: 403 Forbidden on {url}. Check API Key.")
            elif sc==401: 
                api_err="Non autorisé (401)"
                logger.critical(f"CRITICAL: 401 Unauthorized on {url}. Headers:{self.headers}")
            logger.error(f"HTTP API Error for {game_name}#{cl_tag} ({api_err}): {e}")
            res['display']=f"Err API: {api_err}"; res['error']=True; return {**res, **{'display': f"Err API: {api_err}"}}
        except requests.exceptions.RequestException as e: 
            logger.error(f"Network API Error for {game_name}#{cl_tag}: {e}")
            res['display']="Erreur Réseau"; res['error']=True; return {**res, **{'display': "Erreur Réseau"}}
        except Exception as e: 
            logger.error(f"Unexpected Sync Error for {game_name}#{cl_tag}: {e}", exc_info=True)
            res['display']=f"Erreur: {str(e)}"; res['error']=True; return {**res, **{'display': f"Erreur: {str(e)}"}}

    def get_champion_mastery_sync(self, puuid, region_id):
        if not puuid: 
            return None
        try:
            ep = self.get_region_endpoints(region_id)
            url = f"{ep['mastery']}/lol/champion-mastery/v4/champion-masteries/by-puuid/{puuid}/top?count=3"
            r = self.http_session.get(url, timeout=10)
            r.raise_for_status()
            data = r.json()
            top = []
            if isinstance(data, list):
                for m in data:
                    cid = str(m.get('championId'))
                    cname = self.champion_id_map.get(cid, f"ID:{cid}")
                    lvl=m.get('championLevel')
                    pts=m.get('championPoints')
                    if cname and lvl is not None and pts is not None: 
                        top.append({'name':cname, 'level':lvl, 'points':pts})
            return top
        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 404: 
                logger.error(f"API Mastery HTTP Error {e.response.status_code} for {puuid[:8]}: {e}")
        except Exception as e: 
            logger.error(f"Mastery Error for PUUID {puuid[:8]}: {e}", exc_info=True)
        return None

    def analyze_match_history_sync(self, puuid, region_endpoints):
        match_ids = self.get_match_history_sync(puuid, region_endpoints, count=MATCH_HISTORY_COUNT, queue_id=420)
        wins, losses = 0, 0
        recent_champions = []
        default_stats = {'total_games':0, 'wins':0, 'losses':0, 'win_rate':0, 'top_champions':[]}
        if not match_ids: 
            logger.info(f"No recent ranked matches (queue 420, count {MATCH_HISTORY_COUNT}) found for PUUID {puuid[:8]}.")
            return default_stats
        logger.info(f"Found {len(match_ids)} match IDs for PUUID {puuid[:8]} to analyze.")
        match_details_results = []
        for match_id in match_ids:
            if not self.app_running: 
                return default_stats
            detail = self.get_match_details_sync(match_id, region_endpoints)
            if detail: 
                match_details_results.append(detail)
            else: 
                logger.warning(f"No details for match_id {match_id}")
            time.sleep(0.02) 
        for match_details in match_details_results:
            if not self.app_running: 
                return default_stats
            if not match_details or 'info' not in match_details: 
                logger.warning(f"Malformed match_details for PUUID {puuid[:8]}")
                continue
            for p in match_details['info'].get('participants',[]):
                if p.get('puuid') == puuid:
                    won_match = p.get('win', False)
                    if won_match: 
                        wins += 1
                    else: 
                        losses += 1
                    champ_name = p.get('championName', '?')
                    recent_champions.append(champ_name)
                    break
        total_analyzed = wins + losses
        if total_analyzed == 0 and len(match_ids) > 0 : 
            logger.warning(f"PUUID {puuid[:8]} not found in any of the {len(match_ids)} fetched matches.")
        win_rate = (wins / total_analyzed * 100) if total_analyzed > 0 else 0.0
        top_3_champions = Counter(recent_champions).most_common(3)
        logger.info(f"Match analysis for {puuid[:8]}: {wins}W-{losses}L in {total_analyzed} games. Top champs: {top_3_champions}")
        return {'total_games':total_analyzed, 'wins':wins, 'losses':losses, 'win_rate':win_rate, 'top_champions':top_3_champions}

    def get_match_history_sync(self, puuid, region_endpoints, count=20, queue_id=None):
        try:
            base_url = f"{region_endpoints['match']}/lol/match/v5/matches/by-puuid/{puuid}/ids"
            params = {'start': 0, 'count': count}
            if queue_id is not None: 
                params['queue'] = queue_id
            url = f"{base_url}?{urllib.parse.urlencode(params)}"
            logger.info(f"Fetching match history: {url}")
            r = self.http_session.get(url, timeout=10)
            r.raise_for_status()
            match_ids_returned = r.json()
            logger.info(f"Match history for {puuid[:8]} (queue {queue_id}, count {count}) returned {len(match_ids_returned)} IDs.")
            return match_ids_returned
        except requests.exceptions.HTTPError as e:
             if e.response.status_code == 404: 
                 logger.info(f"Match history 404 for PUUID {puuid[:8]} (queue: {queue_id}, count: {count}) - no games?")
             else: 
                 logger.error(f"HTTP error fetching match history for PUUID {puuid[:8]}: {e}")
        except Exception as e: 
            logger.error(f"Error fetching match history for PUUID {puuid[:8]}: {e}", exc_info=True)
        return []

    def get_match_details_sync(self, match_id, region_endpoints):
        try:
             url=f"{region_endpoints['match']}/lol/match/v5/matches/{match_id}"
             logger.debug(f"Fetching match details: {url}")
             r=self.http_session.get(url, timeout=10)
             r.raise_for_status()
             return r.json()
        except requests.exceptions.HTTPError as e: 
            logger.error(f"HTTP error fetching match details for {match_id}: {e.response.status_code} - {e.response.text[:100]}")
        except Exception as e: 
            logger.error(f"Error fetching match details for {match_id}: {e}", exc_info=True)
        return None

    def _update_ui_list_refresh(self, fetched_data, previous_selection):
        if not self.app_running: 
            return
        logger.info(f"Updating UI list with {len(fetched_data) if fetched_data else 'no'} items. Previous selection: {previous_selection}")
        while self.accounts_layout.count(): 
            item = self.accounts_layout.takeAt(0)
            widget = item.widget()
            if widget: 
                widget.deleteLater()
        self.account_widgets = {}
        if not fetched_data: 
            self.update_status("Aucune donnée reçue.", "red", False)
            self.accounts_layout.addWidget(QLabel("Erreur chargement liste."))
            return
        
        sorted_keys = sorted(list(fetched_data.keys())) if isinstance(fetched_data, dict) else []
        first_key = None
        
        for key in sorted_keys:
            if not first_key: 
                first_key = key
            data = fetched_data[key]
            s_info = data.get('summoner')
            if key not in self.comptes or not s_info: 
                logger.warning(f"Skipping account {key} in UI refresh due to missing main data or summoner info.")
                continue
            if key not in self.detailed_stats_cache: 
                self.detailed_stats_cache[key] = {}
            self.detailed_stats_cache[key]['summoner'] = s_info
            account_data = self.comptes[key]
            acc_widget = self._create_single_account_widget(key, account_data, s_info)
            self.accounts_layout.addWidget(acc_widget)
            self.account_widgets[key] = acc_widget
        
        new_sel = previous_selection if previous_selection in self.account_widgets else first_key
        if new_sel:
            QTimer.singleShot(10, lambda k=new_sel: self._select_account_ui(k))
        else: 
            self.stats_label.setText("Aucun compte.")
            self.mastery_label.setText("")
            self.selected_account_key = None
        logger.info(f"UI list refreshed. New selection: {new_sel}")


    def _update_ui_details(self, account_key, detail_data):
        if not self.app_running or account_key not in self.detailed_stats_cache: 
            logger.info(f"Skipping detail update for {account_key} (app closed or key not in cache)")
            return
        if detail_data:
            if 'stats' in detail_data: 
                self.detailed_stats_cache[account_key]['stats'] = detail_data['stats']
            if 'mastery' in detail_data: 
                self.detailed_stats_cache[account_key]['mastery'] = detail_data['mastery']
        else: 
            logger.warning(f"No detail data received for {account_key} in _update_ui_details")
        if account_key == self.selected_account_key: 
            logger.info(f"Updating details display for selected: {account_key}")
            self.afficher_stats_details(account_key)

    def _on_account_clicked(self, selected_key): 
        self._select_account_ui(selected_key)

    def _select_account_ui(self, selected_key):
        if not self.app_running: 
            return
        if selected_key == self.selected_account_key and selected_key in self.account_widgets and self.account_widgets[selected_key].property("selected"):
             self.trigger_detail_fetch_if_needed(selected_key) 
             return
        logger.info(f"Account selected: {selected_key}")
        if self.selected_account_key and self.selected_account_key in self.account_widgets:
             widget = self.account_widgets[self.selected_account_key]
             widget.setProperty("selected", False)
             widget.style().unpolish(widget)
             widget.style().polish(widget)
        self.selected_account_key = selected_key
        if self.selected_account_key in self.account_widgets:
             widget = self.account_widgets[self.selected_account_key]
             widget.setProperty("selected", True)
             widget.style().unpolish(widget)
             widget.style().polish(widget)
        else: 
            logger.warning(f"Widget key {selected_key} not found during selection.")
            self.selected_account_key = None 
        self.afficher_stats_details(selected_key)
        self.trigger_detail_fetch_if_needed(selected_key)

    def trigger_detail_fetch_if_needed(self, key_to_check):
        if not key_to_check or not self.app_running: 
            return
        needs_mastery_fetch = True
        needs_stats_fetch = True
        current_time = time.time()
        summoner_ok = False
        puuid = None
        if key_to_check in self.detailed_stats_cache:
             s_info = self.detailed_stats_cache[key_to_check].get('summoner')
             if s_info and not s_info.get('error'): 
                 summoner_ok = True
                 puuid = s_info.get('puuid')
             cached_mastery = self.api_cache.get(key_to_check, {}).get("mastery")
             if cached_mastery and (current_time - cached_mastery.get("timestamp", 0)) < CACHE_TTL_DETAIL:
                 needs_mastery_fetch = False
                 if 'mastery' not in self.detailed_stats_cache[key_to_check] or self.detailed_stats_cache[key_to_check].get('mastery') != cached_mastery.get('data'): 
                      self.detailed_stats_cache[key_to_check]['mastery'] = cached_mastery.get('data')
                      if key_to_check == self.selected_account_key: 
                          self.afficher_stats_details(key_to_check)
             cached_stats = self.api_cache.get(key_to_check, {}).get("match_stats")
             if cached_stats and (current_time - cached_stats.get("timestamp", 0)) < CACHE_TTL_DETAIL:
                 needs_stats_fetch = False
                 if 'stats' not in self.detailed_stats_cache[key_to_check] or self.detailed_stats_cache[key_to_check].get('stats') != cached_stats.get('data'): 
                      self.detailed_stats_cache[key_to_check]['stats'] = cached_stats.get('data')
                      if key_to_check == self.selected_account_key: 
                          self.afficher_stats_details(key_to_check)
        if (needs_mastery_fetch or needs_stats_fetch) and summoner_ok and puuid:
            if not self.detail_fetch_thread or not self.detail_fetch_thread.isRunning():
                logger.info(f"Launching detail fetch thread for {key_to_check} (Mastery: {needs_mastery_fetch}, Stats: {needs_stats_fetch})")
                region = self.comptes[key_to_check]['region']
                self.detail_fetch_thread = DetailFetchThread(key_to_check, puuid, region, self)
                self.detail_fetch_thread.result_ready.connect(self.handle_api_results)
                self.detail_fetch_thread.start()
            else: 
                logger.info(f"Detail fetch thread for {key_to_check} already running or details not needed/stale.")
        elif not summoner_ok and key_to_check == self.selected_account_key: 
            self.afficher_stats_details(key_to_check)

    def afficher_stats_details(self, account_key):
        if not account_key: 
            self.stats_label.setText("Aucun compte sélectionné.")
            self.mastery_label.setText("")
            self.stats_title_label.setText(f"Stats ({MATCH_HISTORY_COUNT} Classées)")
            return
        logger.info(f"Displaying Stats/Mastery for {account_key}")
        cached_data = self.detailed_stats_cache.get(account_key)
        self.mastery_label.setText("") 
        if not cached_data: 
            self.stats_label.setText("Données indisponibles.")
            self.mastery_label.setText("Données indisponibles.")
            self.stats_title_label.setText(f"Stats ({MATCH_HISTORY_COUNT} Classées)")
            return
        stats = cached_data.get('stats')
        mastery = cached_data.get('mastery')
        s_info = cached_data.get('summoner',{})
        summoner_error = s_info.get('error', False)
        summoner_display_error = s_info.get('display', "Erreur inconnue")
        logger.debug(f" - Cache for {account_key}: summoner_error={summoner_error}, stats_loaded={stats is not None}, mastery_loaded={mastery is not None}")
        self.stats_title_label.setText(f"Stats ({MATCH_HISTORY_COUNT} Classées)")
        if stats is None:
            if summoner_error: 
                self.stats_label.setText(f"Stats indisponibles.\n({summoner_display_error})")
            else: 
                self.stats_label.setText("Chargement stats...")
        elif stats and stats['total_games'] > 0:
            self.stats_title_label.setText(f"Stats ({stats['total_games']}/{MATCH_HISTORY_COUNT} analysées)")
            stats_text = (f"V:{stats['wins']} | D:{stats['losses']}\nWR: {stats['win_rate']:.1f}%\n\nChamps récents ({stats['total_games']}p):\n")
            if stats['top_champions']: 
                stats_text += "\n".join([f" - {c_name}: {n_games} p." for c_name, n_games in stats['top_champions']])
            else: 
                stats_text += " - Aucune donnée champ."
            self.stats_label.setText(stats_text)
        elif stats : 
            self.stats_label.setText(f"0 partie classée pertinente trouvée sur {MATCH_HISTORY_COUNT} dernières vérifiées.")
        else: 
            self.stats_label.setText("Stats indisponibles.") 

        if mastery is None:
            if summoner_error: 
                self.mastery_label.setText(f"Maîtrise indisponible.\n({summoner_display_error})")
            else: 
                self.mastery_label.setText("Chargement maîtrise...")
        elif mastery:
            mastery_text = ""
            if mastery: 
                mastery_text = "\n".join([f" - {champ['name']} (N.{champ['level']})\n   {champ['points']:,} pts".replace(',',' ') for champ in mastery])
            else: 
                mastery_text = "Aucune donnée maîtrise."
            self.mastery_label.setText(mastery_text if mastery_text else "Aucune donnée maîtrise.")
        else: 
            self.mastery_label.setText("Maîtrise non chargée ou vide.")

    def ajouter_compte(self):
        dialog = AccountDialog(list(self.region_map.keys()), parent=self)
        if dialog.exec():
            new_data = dialog.get_data()
            if new_data: 
                n, gn, tg, un, pw, rg = new_data
                if n in self.comptes: 
                    QMessageBox.critical(self, "Erreur", f"Le nom interne '{n}' existe déjà.")
                    return
                try: 
                    pwc = cipher.encrypt(pw.encode()).decode()
                except Exception as e: 
                    logger.error(f"Password encryption error: {e}", exc_info=True)
                    QMessageBox.critical(self, "Erreur Chiffrement", f"Erreur chiffrement mot de passe:\n{e}")
                    return
                self.comptes[n] = {"game_name":gn, "tag_line":tg.lstrip('#'), "username":un, "password":pwc, "region":rg.upper()}
                sauvegarder_comptes(self.comptes)
                self.selected_account_key = n 
                self._refresh_ui_list_sync() 
                self.trigger_detail_fetch_if_needed(n)

    def modifier_compte(self):
        key = self.selected_account_key
        if not key: 
            QMessageBox.warning(self, "Aucune Sélection", "Sélectionnez un compte à modifier.")
            return
        if key not in self.comptes: 
            logger.error(f"Attempted to modify non-existent account key: {key}")
            QMessageBox.critical(self, "Erreur Interne", f"Compte '{key}' introuvable.")
            return
        current_data = self.comptes[key]
        d_pw = ""
        try: 
            d_pw = cipher.decrypt(current_data.get('password','').encode()).decode()
        except Exception as e: 
            logger.warning(f"Could not decrypt password for modification of {key}: {e}")
        dialog = AccountDialog(list(self.region_map.keys()), parent=self, current_data={"name": key, "game_name": current_data.get('game_name',''), "tag_line": current_data.get('tag_line',''), "username": current_data.get('username',''), "password": d_pw, "region": current_data.get('region','EUW1')})
        if dialog.exec():
            new_data = dialog.get_data()
            if new_data:
                gn, tg, un, pw, rg = new_data[1:]
                try: 
                    pwc = cipher.encrypt(pw.encode()).decode()
                except Exception as e: 
                    logger.error(f"Password encryption error during modification: {e}", exc_info=True)
                    QMessageBox.critical(self, "Erreur Chiffrement", f"Erreur chiffrement mot de passe:\n{e}")
                    return
                self.comptes[key].update({"game_name":gn, "tag_line":tg.lstrip('#'), "username":un, "password":pwc, "region":rg.upper()})
                sauvegarder_comptes(self.comptes)
                if key in self.api_cache: 
                    del self.api_cache[key]
                    logger.info(f"Removed API cache for modified account: {key}")
                if key in self.detailed_stats_cache: 
                    del self.detailed_stats_cache[key]
                    logger.info(f"Removed detailed stats cache for modified account: {key}")
                self._refresh_ui_list_sync()
                self.trigger_detail_fetch_if_needed(key)


    def supprimer_compte(self):
        key = self.selected_account_key
        if not key: 
            QMessageBox.warning(self, "Aucune Sélection", "Sélectionnez un compte à supprimer.")
            return
        if key not in self.comptes: 
            logger.error(f"Attempted to delete non-existent account key: {key}")
            QMessageBox.critical(self, "Erreur Interne", f"Compte '{key}' introuvable.")
            return
        reply = QMessageBox.question(self, "Confirmation", f"Êtes-vous sûr de vouloir supprimer le compte '{key}' ?\nCette action est irréversible.", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.comptes[key]
            sauvegarder_comptes(self.comptes)
            if key in self.api_cache: 
                del self.api_cache[key]
                logger.info(f"Removed API cache for deleted account: {key}")
            if key in self.detailed_stats_cache: 
                del self.detailed_stats_cache[key]
                logger.info(f"Removed detailed stats cache for deleted account: {key}")
            self.selected_account_key = None 
            self._refresh_ui_list_sync()
            QMessageBox.information(self, "Succès", f"Compte '{key}' supprimé.")

    def lancer_connexion_auto_selected(self):
        if self.selected_account_key: 
            self.lancer_connexion_auto(self.selected_account_key)
        else: 
            QMessageBox.warning(self, "Aucune Sélection", "Veuillez cliquer sur un compte dans la liste pour le sélectionner.")

    def lancer_connexion_auto(self, nom_key):
        logger.info(f"Attempting auto-login for: {nom_key}")
        if nom_key not in self.comptes: 
            self.update_status("Err: Compte introuvable.", "red", False)
            logger.error(f"Account key '{nom_key}' not found for auto-login.")
            QMessageBox.critical(self, "Erreur Interne", f"Compte '{nom_key}' non trouvé.")
            return
        try:
            data = self.comptes[nom_key]
            user = data.get("username")
            pwd_c = data.get("password")
            if not user or not pwd_c: 
                self.update_status("Err: Données manquantes.", "red", False)
                logger.error(f"Missing username or password for '{nom_key}'.")
                QMessageBox.critical(self, "Erreur Données", f"Login ou MDP manquant pour '{nom_key}'.")
                return
            pwd = cipher.decrypt(pwd_c.encode()).decode()
        except Exception as e: 
            self.update_status("Err déchiffrement MDP.", "red", False)
            logger.error(f"Error decrypting password for '{nom_key}': {e}", exc_info=True)
            QMessageBox.critical(self, "Erreur Données", f"Erreur déchiffrement MDP pour '{nom_key}':\n{e}")
            return
        if self.launch_thread and self.launch_thread.isRunning(): 
            QMessageBox.warning(self, "En cours", "Un lancement de compte est déjà en cours.")
            return
        self.update_status(f"Préparation lancement {user}...", "orange", False)
        self.launch_thread = LaunchThread(user, pwd, self)
        self.launch_thread.update_status_signal.connect(self.update_status)
        self.launch_thread.show_message_signal.connect(self.show_message_box)
        self.launch_thread.start()

    def fermer_client_lol_sync(self):
        if not self.launch_thread: 
             logger.warning("fermer_client_lol_sync called without an active launch_thread.")
             return False 

        self.launch_thread.update_status_signal.emit("Fermeture clients LoL/Riot...", "orange", False)
        found_terminated=False
        p_names=["LeagueClient.exe","RiotClientServices.exe","LeagueClientUx.exe","LeagueClientUxRender.exe","RiotClientUx.exe","RiotClientUxRender.exe", "Riot Client.exe"]
        logger.info(f"Attempting to terminate processes: {', '.join(p_names)}")
        for p in psutil.process_iter(['pid','name']):
            try:
                if p.info['name'] in p_names: 
                    logger.info(f"Terminating: {p.info['name']} (PID: {p.info['pid']})")
                    p.terminate()
                    found_terminated=True
            except (psutil.NoSuchProcess, psutil.AccessDenied): 
                continue
            except Exception as e: 
                logger.error(f"Error terminating {p.info.get('name','?')}: {e}")
        if found_terminated: 
            time.sleep(3.5) 
        killed = False
        for p in psutil.process_iter(['pid','name']):
            try:
                if p.info['name'] in p_names: 
                    logger.info(f"Force killing: {p.info['name']} (PID: {p.info['pid']})")
                    p.kill()
                    killed=True
            except (psutil.NoSuchProcess, psutil.AccessDenied): 
                continue
            except Exception as e: 
                logger.error(f"Error force killing {p.info.get('name','?')}: {e}")
        if killed: 
            time.sleep(1.5)
        still_running = [p.info['name'] for p in psutil.process_iter(['name']) if p.info.get('name') in p_names]
        if still_running: 
            logger.warning(f"Processes still active: {', '.join(still_running)}")
            self.launch_thread.update_status_signal.emit("Fermeture partielle.", "orange", False)
            return False
        else: 
            logger.info("Clients closed.")
            self.launch_thread.update_status_signal.emit("Clients fermés.", "green", False)
            return True

    def lancer_client_lol_sync(self, username, password):
        if not self.launch_thread: 
            logger.error("lancer_client_lol_sync called without an active launch_thread for status updates.")
            return False

        riot_paths = ["C:\\Riot Games\\Riot Client\\RiotClientServices.exe", os.path.expanduser("~\\AppData\\Local\\Riot Games\\Riot Client\\RiotClientServices.exe")]
        rp = next((p for p in riot_paths if os.path.exists(p)), None)
        if not rp: 
            self.launch_thread.update_status_signal.emit("Err: RiotClientServices.exe non trouvé.","red",False)
            self.launch_thread.show_message_signal.emit("Erreur Chemin",f"RiotClientServices.exe introuvable:\n{chr(10).join(riot_paths)}")
            logger.error(f"RiotClientServices.exe not found: {riot_paths}")
            return False
        self.launch_thread.update_status_signal.emit("Lancement Riot Client...","orange",False)
        try: 
            subprocess.Popen([rp])
            logger.info(f"Riot Client launched: {rp}")
        except Exception as e: 
            self.launch_thread.update_status_signal.emit("Erreur lancement Riot.","red",False)
            self.launch_thread.show_message_signal.emit("Erreur Lancement",f"Impossible de lancer {rp}:\n{e}")
            logger.error(f"Failed to launch {rp}: {e}", exc_info=True)
            return False
        self.launch_thread.update_status_signal.emit("Attente processus 'Riot Client.exe'...", "orange", False)
        if not attendre_processus("Riot Client.exe", timeout=30): 
            self.launch_thread.update_status_signal.emit("Err: 'Riot Client.exe' non détecté.", "red", False)
            self.launch_thread.show_message_signal.emit("Timeout Processus", "'Riot Client.exe' non démarré.")
            return False
        self.launch_thread.update_status_signal.emit("Activation fenêtre Riot...", "orange", False)
        hwnd_riot = None
        start_time_activation = time.time() # Renamed local variable
        timeout_activation = 20 
        while time.time() - start_time_activation < timeout_activation:
            hwnd_riot = activer_fenetre_riot()
            if hwnd_riot and win32gui.GetForegroundWindow() == hwnd_riot: 
                break
            time.sleep(0.75) 
        if not hwnd_riot: 
            self.launch_thread.update_status_signal.emit("Err: Fenêtre Riot introuvable.", "red", False)
            self.launch_thread.show_message_signal.emit("Erreur Fenêtre", "Fenêtre Riot Client introuvable.")
            return False
        elif win32gui.GetForegroundWindow() != hwnd_riot : 
            logger.warning("Riot window found but not activated. Attempting automation.")
            self.launch_thread.update_status_signal.emit("Fenêtre non active, tentative...", "orange", False)
        time.sleep(1.5)
        login_region = None 
        logger.info("Searching for Username field...")
        if not self.trouver_et_cliquer_sync("USERNAME.png", timeout=15, confidence=0.7, region=login_region): 
            self.launch_thread.update_status_signal.emit("Champ username non trouvé.", "red", False)
            self.launch_thread.show_message_signal.emit("Erreur Automatisation", "Champ 'Username' non trouvé.")
            return False
        try: 
            pyperclip.copy(username)
            pyautogui.hotkey('ctrl', 'v')
            logger.info("Username pasted.")
            time.sleep(0.3)
        except Exception as e: 
            logger.error(f"Error pasting username: {e}", exc_info=True)
            self.launch_thread.show_message_signal.emit("Erreur Automatisation", f"Erreur collage username:\n{e}")
            return False
        try: 
            logger.info("Pressing Tab for password...")
            pyautogui.press('tab')
            time.sleep(0.3)
            logger.info("Pasting password...")
            pyperclip.copy(password)
            pyautogui.hotkey('ctrl', 'v')
            logger.info("Password pasted.")
            time.sleep(0.5)
        except Exception as e: 
            logger.error(f"Error Tab/Pasting password: {e}", exc_info=True)
            self.launch_thread.show_message_signal.emit("Erreur Automatisation", f"Erreur Tab/Collage password:\n{e}")
            return False
        logger.info("Searching for Login/Validate button...")
        login_button_coords = self.attendre_image_sync("VALIDER IDENTIFIANTS.png", timeout=5, confidence=0.7, region=login_region)
        if not login_button_coords: 
            logger.info("'VALIDER IDENTIFIANTS.png' not found, trying 'LOGIN_BUTTON_ALT.png'...")
            login_button_coords = self.attendre_image_sync("LOGIN_BUTTON_ALT.png", timeout=5, confidence=0.7, region=login_region)
        if not self.cliquer_coord_sync(login_button_coords, image_name_debug="Login Button"): 
            self.launch_thread.update_status_signal.emit("Bouton connexion non trouvé.", "red", False)
            self.launch_thread.show_message_signal.emit("Erreur Automatisation", "Bouton connexion non trouvé.")
            return False
        self.launch_thread.update_status_signal.emit("Connexion en cours...", "blue", False)
        time.sleep(5.0) 
        logger.info("Searching for Play button (post-login)...")
        play_region = None 
        play_coords = self.attendre_image_sync("beforeplay.png", timeout=15, confidence=0.7, region=play_region)
        if play_coords: 
            logger.info("'beforeplay.png' found, clicking...")
            self.cliquer_coord_sync(play_coords, image_name_debug="BeforePlay")
            time.sleep(1.0)
            play_coords = self.attendre_image_sync("Play.png", timeout=10, confidence=0.7, region=play_region)
        else: 
            logger.info("Warning: 'beforeplay.png' not found, searching 'Play.png'.")
            play_coords = self.attendre_image_sync("Play.png", timeout=15, confidence=0.7, region=play_region)
        if play_coords: 
            logger.info("'Play.png' found, clicking...")
            self.cliquer_coord_sync(play_coords, image_name_debug="Play")
            self.launch_thread.update_status_signal.emit("Client LoL lancé!", "green", False)
        else: 
            logger.warning("Final 'Play' button not found.")
            self.launch_thread.update_status_signal.emit("Connexion réussie (Play?)", "yellow", False)
        return True

    def attendre_image_sync(self, image_name, timeout=20, confidence=0.7, region=None):
        start_time_wait_img = time.time() # Renamed to avoid conflict
        while time.time() - start_time_wait_img < timeout:
            coords = self.trouver_image(image_name, confidence=confidence, region=region)
            if coords:
                return coords
            time.sleep(0.25) 
        return None


    def cliquer_coord_sync(self, coords, image_name_debug="coord"):
        if coords: 
            cx, cy = coords
            time.sleep(0.1)
            pyautogui.moveTo(cx, cy, duration=0.1)
            pyautogui.click(cx, cy)
            logger.info(f"Clicked {image_name_debug} @({cx},{cy})")
            time.sleep(0.5)
            return True
        return False

    def trouver_et_cliquer_sync(self, image_name, timeout=10, confidence=0.7, region=None):
        coords = self.attendre_image_sync(image_name, timeout=timeout, confidence=confidence, region=region)
        return self.cliquer_coord_sync(coords, image_name_debug=image_name)

    def closeEvent(self, event):
        logger.info("Close event triggered. Shutting down application.")
        self.app_running = False 
        
        threads_to_join = []
        if self.update_thread and self.update_thread.isRunning(): threads_to_join.append(self.update_thread)
        if self.detail_fetch_thread and self.detail_fetch_thread.isRunning(): threads_to_join.append(self.detail_fetch_thread)
        if self.launch_thread and self.launch_thread.isRunning(): threads_to_join.append(self.launch_thread)

        for t in threads_to_join:
            thread_name = t.objectName() if t.objectName() else type(t).__name__
            logger.info(f"Waiting for thread {thread_name} to finish...")
            if not t.wait(2000): 
                logger.warning(f"Thread {thread_name} did not finish in time.")

        logger.info("Saving API cache...")
        self._save_api_cache()
        
        logger.info("Shutting down API executor...")
        if sys.version_info >= (3, 9):
            self.api_executor.shutdown(wait=True, cancel_futures=True)
        else:
            self.api_executor.shutdown(wait=True)
            
        logger.info("Application cleanup finished. Accepting close event.")
        event.accept()

class AccountDialog(QDialog):
    def __init__(self, region_list, parent=None, current_data=None):
        super().__init__(parent)
        self.is_edit_mode = current_data is not None
        self.region_list = region_list if region_list else ["EUW1"] 

        if self.is_edit_mode:
            self.setWindowTitle(f"Modifier {current_data.get('name', '')}")
        else:
            self.setWindowTitle("Ajouter Compte")

        self.setMinimumWidth(450)
        if parent: 
            self.setStyleSheet(parent.styleSheet())

        layout = QGridLayout(self)
        layout.setSpacing(10)
        self.fields = {}
        field_labels = ["Nom:", "Game Name:", "Tag Line:", "Login:", "Pass:", "Région:"]
        
        for i, label_text in enumerate(field_labels):
            label = QLabel(label_text)
            layout.addWidget(label, i, 0)
            entry = None 
            if label_text == "Nom:" and self.is_edit_mode:
                entry = QLabel(current_data.get('name', ''))
                entry.setStyleSheet("font-weight: bold;")
            elif label_text == "Pass:":
                entry = QLineEdit()
                entry.setEchoMode(QLineEdit.Password)
            elif label_text == "Région:":
                entry = QComboBox()
                entry.addItems(self.region_list)
            else:
                entry = QLineEdit()
            
            self.fields[label_text] = entry
            if not (label_text == "Nom:" and self.is_edit_mode) : 
                 layout.addWidget(self.fields[label_text], i, 1, 1, 2)
            elif (label_text == "Nom:" and self.is_edit_mode): 
                 layout.addWidget(self.fields[label_text], i, 1, 1, 2)


            if label_text == "Tag Line:":
                hint_label = QLabel("(sans le #)")
                hint_label.setStyleSheet("font-size: 8pt; color: gray;")
                layout.addWidget(hint_label, i, 3)
                
        if self.is_edit_mode:
            self.fields["Game Name:"].setText(current_data.get('game_name', ''))
            self.fields["Tag Line:"].setText(current_data.get('tag_line', ''))
            self.fields["Login:"].setText(current_data.get('username', ''))
            self.fields["Pass:"].setText(current_data.get('password', '')) 
            current_region = current_data.get('region', self.region_list[0] if self.region_list else "EUW1")
            if current_region in self.region_list:
                self.fields["Région:"].setCurrentText(current_region)
            elif self.region_list: 
                 self.fields["Région:"].setCurrentIndex(0)
        elif not self.is_edit_mode and self.region_list: 
             self.fields["Région:"].setCurrentIndex(0)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept_with_validation)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box, len(field_labels), 0, 1, 4)
        self.setLayout(layout)

    def accept_with_validation(self):
        name_val = ""
        if not self.is_edit_mode:
            name_val = self.fields["Nom:"].text().strip()
            if not name_val:
                QMessageBox.warning(self, "Validation Erreur", "Le champ 'Nom' est requis.")
                self.fields["Nom:"].setFocus()
                return
        
        game_name_val = self.fields["Game Name:"].text().strip()
        if not game_name_val:
            QMessageBox.warning(self, "Validation Erreur", "Le champ 'Game Name' est requis.")
            self.fields["Game Name:"].setFocus()
            return

        tag_line_val = self.fields["Tag Line:"].text().strip().lstrip('#') 
        if not tag_line_val:
            QMessageBox.warning(self, "Validation Erreur", "Le champ 'Tag Line' est requis.")
            self.fields["Tag Line:"].setFocus()
            return
            
        login_val = self.fields["Login:"].text().strip()
        if not login_val:
            QMessageBox.warning(self, "Validation Erreur", "Le champ 'Login' est requis.")
            self.fields["Login:"].setFocus()
            return

        pass_val = self.fields["Pass:"].text()
        if not pass_val: 
            QMessageBox.warning(self, "Validation Erreur", "Le champ 'Pass' est requis.")
            self.fields["Pass:"].setFocus()
            return
            
        region_val = self.fields["Région:"].currentText()
        if not region_val: 
            QMessageBox.warning(self, "Validation Erreur", "Le champ 'Région' est requis.")
            self.fields["Région:"].setFocus()
            return

        self.accept() 

    def get_data(self):
        name_val = ""
        if self.is_edit_mode:
            name_val = self.fields["Nom:"].text() 
        else:
            name_val = self.fields["Nom:"].text().strip() 

        return (
            name_val,
            self.fields["Game Name:"].text().strip(),
            self.fields["Tag Line:"].text().strip().lstrip('#'),
            self.fields["Login:"].text().strip(),
            self.fields["Pass:"].text(), 
            self.fields["Région:"].currentText().strip().upper()
        )

if __name__ == "__main__":
    setup_logging()
    logger.info("Application starting...")
    
    os.makedirs(CACHE_DIR, exist_ok=True)
    logger.info(f"Cache directory '{CACHE_DIR}' ensured.")
    
    cv_images_path = resource_path("CV_Images")
    os.makedirs(cv_images_path, exist_ok=True)
    logger.info(f"CV_Images directory '{cv_images_path}' ensured.")

    ranked_emblems_path = resource_path("ranked_emblems")
    os.makedirs(ranked_emblems_path, exist_ok=True)
    logger.info(f"Ranked_emblems directory '{ranked_emblems_path}' ensured.")

    app = QApplication(sys.argv)
    window = LolSwitcherApp()
    window.show()
    sys.exit(app.exec())
