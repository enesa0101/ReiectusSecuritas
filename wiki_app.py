import sys
import sqlite3
import requests
import socket
import os

# Ana dizini path'e ekle (Modül hatalarını önlemek için)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import hashlib
import string
import random
import json
import shutil

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    import sys, os
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, 
                             QHBoxLayout, QVBoxLayout, QListWidget, 
                             QTextBrowser, QLineEdit, QPushButton, QLabel,
                             QTabWidget, QFormLayout, QSpinBox, QComboBox, QFileDialog, QMessageBox, QFrame,
                             QGroupBox, QSystemTrayIcon, QMenu, QPlainTextEdit, QSizePolicy,
                             QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QSplitter)
from PyQt6.QtGui import QFont, QKeySequence, QColor, QShortcut, QIcon, QPageLayout, QPageSize, QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QMarginsF
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
try:
    from PyQt6.QtPrintSupport import QPrinter
except ImportError:
    QPrinter = None

from Modules.web_scanner import WebScannerEngine
from Modules.file_analyzer import VirusTotalAnalyzer
from Modules.dpi_bypass import DPIBypassManager
from Modules.dos_simulator import SlowlorisThread, _hedef_guvenli_mi
import subprocess
import re
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# ─── ANSI Renk Sabitleri ──────────────────────────────────────────────────
ANSI_FG = {
    '30':'#1c1c1c','31':'#cc2222','32':'#22cc22','33':'#cccc22',
    '34':'#4477ee','35':'#aa22cc','36':'#22cccc','37':'#cccccc',
    '90':'#888888','91':'#ff6666','92':'#66ff66','93':'#ffff66',
    '94':'#88aaff','95':'#ff88ff','96':'#88ffff','97':'#ffffff',
}
ANSI_BG = {
    '40':'#000000','41':'#660000','42':'#006600','43':'#666600',
    '44':'#000066','45':'#660066','46':'#006666','47':'#aaaaaa',
    '100':'#444444','101':'#ff4444','102':'#44ff44','103':'#ffff44',
    '104':'#4466ff','105':'#ff44ff','106':'#44ffff','107':'#ffffff',
}
# CMD color komutu renk tablosu (tek hex hane)
CMD_RENK = {
    '0':'#000000','1':'#0000aa','2':'#00aa00','3':'#00aaaa',
    '4':'#aa0000','5':'#aa00aa','6':'#cc8800','7':'#aaaaaa',
    '8':'#555555','9':'#5555ff','a':'#55ff55','b':'#55ffff',
    'c':'#ff5555','d':'#ff55ff','e':'#ffff55','f':'#ffffff',
}

def ansi_html_cevir(satir: str) -> str:
    """ANSI escape kodlarını HTML span'e çevirir."""
    # HTML özel karakterleri kaçış
    satir = satir.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    parcalar = re.split(r'(\x1b\[[0-9;]*m)', satir)
    sonuc = []
    fg, bg, bold, span_acik = '#cccccc', '', False, False
    for p in parcalar:
        m = re.match(r'\x1b\[([0-9;]*)m', p)
        if m:
            if span_acik:
                sonuc.append('</span>'); span_acik = False
            for k in (m.group(1).split(';') if m.group(1) else ['0']):
                if k in ('0',''):   fg,bg,bold = '#cccccc','',False
                elif k == '1':      bold = True
                elif k == '22':     bold = False
                elif k in ANSI_FG:  fg = ANSI_FG[k]
                elif k in ANSI_BG:  bg = ANSI_BG[k]
            stil = f'color:{fg};'
            if bg:   stil += f'background-color:{bg};'
            if bold: stil += 'font-weight:bold;'
            sonuc.append(f'<span style="{stil}">'); span_acik = True
        else:
            sonuc.append(p)
    if span_acik: sonuc.append('</span>')
    return ''.join(sonuc)

# ─── Terminal Komut Thread ───────────────────────────────────────────────────
class TerminalThread(QThread):
    cikti_sinyali = pyqtSignal(str)   # HTML satırı
    bitti_sinyali = pyqtSignal(int)   # çıkış kodu

    def __init__(self, komut: str, cwd: str):
        super().__init__()
        self.komut = komut
        self.cwd   = cwd
        self._proc = None

    def run(self):
        try:
            # chcp 65001 ile UTF-8 zorla, cmd /c ile tam CMD desteği
            self._proc = subprocess.Popen(
                f'cmd /v /c "chcp 65001 > nul 2>&1 & {self.komut}"',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.cwd,
                encoding='utf-8',
                errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for satir in self._proc.stdout:
                html = ansi_html_cevir(satir.rstrip('\r\n'))
                self.cikti_sinyali.emit(html)
            self._proc.wait()
            self.bitti_sinyali.emit(self._proc.returncode)
        except Exception as e:
            self.cikti_sinyali.emit(f'<span style="color:#ff5555">[HATA] {e}</span>')
            self.bitti_sinyali.emit(-1)

    def iptal(self):
        if self._proc and self._proc.poll() is None:
            try:
                # Alt process'leri de öldür (taskkill /t)
                subprocess.run(
                    ['taskkill', '/f', '/t', '/pid', str(self._proc.pid)],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except:
                self._proc.kill()


# --- CONFIGURATION ---
GITHUB_USER = "enesa0101"
REPO_NAME = "ReiectusSecuritas"

DB_FILE = "reiectus_securitas.db"
MASTER_KEYS_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{REPO_NAME}/main/anahtarlar.json"

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS wiki (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            baslik TEXT UNIQUE,
                            icerik TEXT
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                            anahtar TEXT PRIMARY KEY,
                            deger TEXT
                          )''')
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baslik ON wiki(baslik)")
        
        # Mevcut varsayılanlara eklenen yeni kritik siber güvenlik konuları
        yeni_konular = {
            "DDoS Nedir?": "<h1>DDoS Nedir?</h1><p>Geniş kapsamlı ağ saldırısıdır...</p>",
            "Sızma Testi (Pentest)": "<h1>Sızma Testi Nedir?</h1><p>Sistemlerin güvenliğini test etmek için yapılan yasal saldırı simülasyonudur.</p><ul><li>Black Box</li><li>White Box</li><li>Grey Box</li></ul>",
            "Sıfırıncı Gün (Zero-Day)": "<h1>Zero-Day Nedir?</h1><p>Yazılım üreticisi tarafından henüz bilinmeyen ve yaması olmayan güvenlik açıklarıdır.</p>",
            "Oltalama (Phishing)": "<h1>Phishing Nedir?</h1><p>Kullanıcıları sahte web siteleriyle kandırarak bilgi çalma yöntemidir.</p>",
            "SOC (Security Ops Center)": "<h1>SOC Merkezi</h1><p>Siber tehditlerin 7/24 izlendiği ve müdahale edildiği güvenlik operasyon merkezidir.</p>",
            "Kriptoloji: AES vs RSA": "<h1>Şifreleme Algoritmaları</h1><p>AES simetrik, RSA asimetrik şifrelemenin endüstri standartlarıdır.</p>",
            "Metasploit Nedir?": "<h1>Metasploit Framework</h1><p>Güvenlik açıklarını sömürmek (exploit) için kullanılan en popüler araçtır.</p>",
            "Burp Suite Kullanımı": "<h1>Burp Suite</h1><p>Web uygulama güvenliği testlerinde kullanılan proxy ve tarama aracıdır.</p>",
            "Zafiyet Taraması": "<h1>Nessus & Nmap</h1><p>Sistemdeki açıkları otomatik olarak tarayan yazılımlardır.</p>",
            "ISO 27001 Standartı": "<h1>Bilgi Güvenliği Standartı</h1><p>Bilgi güvenliği yönetim sistemleri için uluslararası kabul görmüş standarttır.</p>",
            "Etik Hackerlık": "<h1>White Hat Hacker</h1><p>Güvenliği artırmak amacıyla yetkili bir şekilde sistemlere sızan kişidir.</p>",
            "OSINT (Açık Kaynak İstihbaratı)": "<h1>OSINT Nedir?</h1><p>Açık kaynaklardan (sosyal medya, arama motorları, kamu kayıtları) yasal yollarla bilgi toplama sürecidir. Hedef hakkında istihbarat toplamanın ilk adımıdır.</p>",
            "Tersine Mühendislik (Reverse)": "<h1>Reverse Engineering</h1><p>Bir yazılımın iç yapısını, kaynak kodu olmadan analiz ederek nasıl çalıştığını anlama sürecidir. Zararlı yazılım analizi için kritiktir.</p>",
            "Adli Bilişim (Forensics)": "<h1>Dijital Forensics</h1><p>Siber saldırı sonrası dijital kanıtların toplanması, korunması ve analiz edilerek raporlanması sürecidir.</p>",
            "Bulut Güvenliği (Cloud)": "<h1>Cloud Security</h1><p>Bulut altyapılarındaki (AWS, Azure vb.) verilerin ve uygulamaların paylaşımlı sorumluluk modeli çerçevesinde korunmasıdır.</p>",
            "IoT Güvenliği": "<h1>Nesnelerin İnterneti (IoT) Güvenliği</h1><p>Akıllı cihazların (IP kameralar, akıllı ev sistemleri) güvenliğini sağlamaya yönelik stratejilerdir.</p>",
            "Buffer Overflow (Bellek Taşması)": "<h1>Buffer Overflow</h1><p>Bir programın bellek kapasitesinden fazla veri alarak komşu bellek alanlarını bozması ve kod yürütülmesine izin vermesidir.</p>",
            "Yetki Yükseltme (Privilege Esc.)": "<h1>Privilege Escalation</h1><p>Düşük yetkili bir kullanıcının, sistemdeki bir açıktan yararlanarak Admin/Root yetkilerine erişmesidir.</p>",
            "Honeypot (Yemlik Sistemler)": "<h1>Honeypot</h1><p>Saldırganları gerçek sistemlerden uzak tutmak ve tekniklerini incelemek için kurulan tuzak sistemlerdir.</p>",
            "SIEM (Olay Yönetimi)": "<h1>SIEM Nedir?</h1><p>Güvenlik loglarını tek bir merkezde toplayıp analiz eden ve tehditleri gerçek zamanlı bildiren sistemdir.</p>",
            "EDR (Uç Nokta Güvenliği)": "<h1>EDR (Endpoint Detection)</h1><p>Bilgisayar ve sunuculardaki şüpheli hareketleri sürekli izleyen ve otomatik müdahale eden güvenlik katmanıdır.</p>"
        }
        
        for baslik, icerik in yeni_konular.items():
            cursor.execute("INSERT OR IGNORE INTO wiki (baslik, icerik) VALUES (?, ?)", (baslik, icerik))
                
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Veritabanı hatası: {e}")

# Port Tarayıcı Thread (Mevcut yapın korundu)
class PortScannerThread(QThread):
    sonuc_sinyali = pyqtSignal(str)
    def __init__(self, ip):
        super().__init__(); self.ip = ip
        self.portlar = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
    def run(self):
        sonuclar = f"<h3>{self.ip} Sonuçları:</h3><ul>"
        for port in self.portlar:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.5)
            if s.connect_ex((self.ip, port)) == 0:
                sonuclar += f"<li style='color:#00ff00'>Port {port}: AÇIK</li>"
            else: sonuclar += f"<li style='color:#ff0000'>Port {port}: KAPALI</li>"
            s.close()
        self.sonuc_sinyali.emit(sonuclar + "</ul>")

# Network (IP/Whois) Thread
class NetworkWorkerThread(QThread):
    sonuc_sinyali = pyqtSignal(dict, str)
    hata_sinyali = pyqtSignal(str)

    def __init__(self, target_ip=None):
        super().__init__()
        self.target_ip = target_ip

    def run(self):
        try:
            url = f"http://ip-api.com/json/{self.target_ip}" if self.target_ip else "http://ip-api.com/json/"
            response = requests.get(url, timeout=10).json()
            ip_val = response.get('query', self.target_ip if self.target_ip else "Bilinmiyor")
            self.sonuc_sinyali.emit(response, ip_val)
        except Exception as e:
            self.hata_sinyali.emit(str(e))

# Dosya Analiz Thread (Yeni: Çökmeyi engellemek için)
class FileAnalyzerThread(QThread):
    sonuc_sinyali = pyqtSignal(str)
    def __init__(self, api_key, file_path):
        super().__init__()
        self.api_key = api_key
        self.file_path = file_path
    def run(self):
        try:
            analyzer = VirusTotalAnalyzer(self.api_key)
            rapor = analyzer.analyze_file(self.file_path)
            self.sonuc_sinyali.emit(rapor)
        except Exception as e:
            self.sonuc_sinyali.emit(f"<h2 style='color:red'>Hata!</h2><p>{str(e)}</p>")



class ReiectusSecuritas(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # --- KRITIK ILK HAZIRLIK ---
        self.active_threads = [] # Tum thread'leri burada tutuyoruz
        self.master_keys = {"shodan": "", "vt": ""}
        self.version = "1.0.0"
        self.dos_thread = None  # DoS simülasyon thread referansı
        self.session_words = set()
        
        # Versiyonu dosyadan oku
        try:
            if os.path.exists("version.txt"):
                with open("version.txt", "r") as f: self.version = f.read().strip()
        except: pass

        self.setWindowTitle(f"Reiectus Securitas v{self.version}")
        self.setWindowIcon(QIcon(resource_path("icon.png")))
        self.setGeometry(100, 100, 1150, 800)
        self.font_size = 14
        self.tema_modu = "Karanlık"
        self.dpi_manager = DPIBypassManager()
        
        # Bulut anahtarlarını çek
        self.bulut_anahtarlari_yukle()
        
        init_db()
        
        # Temayı veritabanından oku
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("SELECT deger FROM settings WHERE anahtar = 'tema'")
            res = cur.fetchone()
            if res: self.tema_modu = res[0]
            conn.close()
        except: pass
        
        self.tema_uygula()
        
        self.sekmeler = QTabWidget()
        self.setCentralWidget(self.sekmeler)
        
        # Sekmeleri oluştur
        self.wiki_sekmesi = QWidget()
        self.araclar_sekmesi = QWidget()
        self.ayarlar_sekmesi = QWidget()
        
        self.sekmeler.addTab(self.wiki_sekmesi, "📚 Bilgi Bankası")
        self.sekmeler.addTab(self.araclar_sekmesi, "🛠 Güvenlik Araçları")
        self.sekmeler.addTab(self.dpi_sekmesi_olustur(), "🔓 DPI Bypass")
        self.sekmeler.addTab(self.dos_sekmesi_olustur(), "⚠️ DoS Lab")
        self.sekmeler.addTab(self.reverse_sekmesi_olustur(), "🔓 Crack Lab")
        self.sekmeler.addTab(self.terminal_sekmesi_olustur(), "💻 Terminal")
        self.sekmeler.addTab(self.ayarlar_sekmesi, "⚙️ Ayarlar")

        
        # Sayfaları doldur ve verileri yükle
        self.wiki_sekmesi_olustur()
        self.araclar_sekmesi_olustur()
        self.ayarlar_sekmesi_olustur()
        self.verileri_yukle()
        self.tema_uygula()

        # Sistem Tepsisi (Tray) Ayarları
        self.really_close = False
        self.sistem_tepsisi_olustur()

    def sistem_tepsisi_olustur(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(resource_path("icon.png")))

        # Menü oluştur
        tray_menu = QMenu()

        goster_action = QAction("📚 Göster", self)
        goster_action.triggered.connect(self.showNormal)
        goster_action.triggered.connect(self.activateWindow)

        cikis_action = QAction("🛑 Tamamen Kapat", self)
        cikis_action.triggered.connect(self.programi_tamamen_kapat)

        tray_menu.addAction(goster_action)
        tray_menu.addSeparator()
        tray_menu.addAction(cikis_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        # Çift tıklama veya tıklama ile açılma
        self.tray_icon.activated.connect(self.tray_icon_tiklandi)

    def tray_icon_tiklandi(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger: # Sol tıklama
            if self.isVisible():
                self.hide()
            else:
                self.showNormal()
                self.activateWindow()
        elif reason == QSystemTrayIcon.ActivationReason.DoubleClick: # Çift tıklama
            self.showNormal()
            self.activateWindow()

    def programi_tamamen_kapat(self):
        """Tray menüsünden tamamen kapatma."""
        try:
            self.dpi_manager.stop_bypass()
        except: pass
        try:
            for thread in self.active_threads:
                if thread.isRunning():
                    thread.terminate()
                    thread.wait()
        except: pass
        try:
            self.tray_icon.hide()
        except: pass
        QApplication.quit()

    def track_thread(self, thread):
        """Thread'leri takip listesine ekler."""
        if not hasattr(self, 'active_threads'):
            self.active_threads = []
        
        if thread not in self.active_threads:
            self.active_threads.append(thread)

    def tema_uygula(self):
        common = f"QWidget {{ font-size: {self.font_size}px; }}"
        if self.tema_modu == "Karanlık":
            self.setStyleSheet(common + f"""
                QMainWindow {{ background-color: #0f172a; }} 
                QWidget {{ color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }} 
                QLineEdit {{ background: #1e293b; color: #38bdf8; border: 1px solid #334155; border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 1px solid #38bdf8; background: #24354f; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #1d4ed8); 
                    color: white; 
                    font-weight: bold; 
                    border: 1px solid #3b82f6; 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #1d4ed8); 
                    border-color: #38bdf8; 
                }} 
                QPushButton:pressed {{
                    background: #60a5fa;
                    color: white;
                }}
                QTextBrowser {{ 
                    background: #1e293b; 
                    color: #f1f5f9; 
                    border: 1px solid #334155; 
                    border-left: 4px solid #38bdf8; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: #1e293b; 
                    color: #38bdf8; 
                    border: 1px solid #334155; 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #1d4ed8);
                    color: white;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(59, 130, 246, 0.2);
                    color: #38bdf8;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #334155; 
                    background: #0f172a; 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: #1e293b; 
                    color: #64748b; 
                    padding: 8px 16px; 
                    border: 1px solid #334155; 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #1d4ed8); 
                    color: white; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: #24354f;
                    color: #38bdf8;
                }}
                QGroupBox {{ 
                    border: 1px solid #334155; 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: #1e293b;
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #38bdf8; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: #1e293b; 
                    color: #f1f5f9; 
                    border: 1px solid #334155; 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: #1e293b; 
                    color: #f1f5f9; 
                    selection-background-color: #3b82f6; 
                    selection-color: white;
                    border: 1px solid #334155;
                }}
                QMessageBox {{ 
                    background-color: #0f172a; 
                    border: 1px solid #334155;
                }}
                QMessageBox QLabel {{ 
                    color: #e2e8f0; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #1d4ed8); 
                    color: white; 
                    font-weight: bold;
                    border: 1px solid #3b82f6; 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: #1e293b;
                    color: #e2e8f0;
                    gridline-color: #334155;
                    border: 1px solid #334155;
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #e2e8f0;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #1d4ed8);
                    color: white;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e293b, stop:1 #0f172a);
                    color: #38bdf8;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid #334155;
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #10b981; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
                        border-color: #059669;
                    }
                    QPushButton:disabled {
                        background: #1e293b;
                        color: #64748b;
                        border: 1px solid #334155;
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f43f5e, stop:1 #e11d48); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f43f5e; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #be123c);
                        border-color: #e11d48;
                    }
                    QPushButton:disabled {
                        background: #1e293b;
                        color: #64748b;
                        border: 1px solid #334155;
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #10b981; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
                        border-color: #059669;
                    }
                    QPushButton:disabled {
                        background: #1e293b;
                        color: #64748b;
                        border: 1px solid #334155;
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f43f5e, stop:1 #e11d48); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f43f5e; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #be123c);
                        border-color: #e11d48;
                    }
                    QPushButton:disabled {
                        background: #1e293b;
                        color: #64748b;
                        border: 1px solid #334155;
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: #0f172a; color: #38bdf8; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #334155;")
                
        elif self.tema_modu == "Aydınlık":
            self.setStyleSheet(common + f"""
                QMainWindow {{ background-color: #f8fafc; }} 
                QWidget {{ color: #0f172a; font-family: 'Segoe UI', sans-serif; }} 
                QLineEdit {{ background: #ffffff; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 1px solid #3b82f6; background: #f1f5f9; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb); 
                    color: white; 
                    font-weight: bold; 
                    border: 1px solid #3b82f6; 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #1d4ed8); 
                    border-color: #2563eb; 
                }} 
                QPushButton:pressed {{
                    background: #60a5fa;
                    color: white;
                }}
                QTextBrowser {{ 
                    background: #ffffff; 
                    color: #0f172a; 
                    border: 1px solid #cbd5e1; 
                    border-left: 4px solid #2563eb; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: #ffffff; 
                    color: #0f172a; 
                    border: 1px solid #cbd5e1; 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb);
                    color: white;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(59, 130, 246, 0.1);
                    color: #2563eb;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #cbd5e1; 
                    background: #f8fafc; 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: #f1f5f9; 
                    color: #64748b; 
                    padding: 8px 16px; 
                    border: 1px solid #cbd5e1; 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb); 
                    color: white; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: #e2e8f0;
                    color: #2563eb;
                }}
                QGroupBox {{ 
                    border: 1px solid #cbd5e1; 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: #ffffff;
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #2563eb; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: #ffffff; 
                    color: #0f172a; 
                    border: 1px solid #cbd5e1; 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: #ffffff; 
                    color: #0f172a; 
                    selection-background-color: #3b82f6; 
                    selection-color: white;
                    border: 1px solid #cbd5e1;
                }}
                QMessageBox {{ 
                    background-color: #f8fafc; 
                    border: 1px solid #cbd5e1;
                }}
                QMessageBox QLabel {{ 
                    color: #0f172a; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb); 
                    color: white; 
                    font-weight: bold;
                    border: 1px solid #3b82f6; 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: #ffffff;
                    color: #0f172a;
                    gridline-color: #cbd5e1;
                    border: 1px solid #cbd5e1;
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #0f172a;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b82f6, stop:1 #2563eb);
                    color: white;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f1f5f9, stop:1 #cbd5e1);
                    color: #2563eb;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid #cbd5e1;
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #34d399, stop:1 #10b981); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #34d399; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669);
                        border-color: #10b981;
                    }
                    QPushButton:disabled {
                        background: #f1f5f9;
                        color: #94a3b8;
                        border: 1px solid #cbd5e1;
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f87171, stop:1 #ef4444); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f87171; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ef4444, stop:1 #dc2626);
                        border-color: #ef4444;
                    }
                    QPushButton:disabled {
                        background: #f1f5f9;
                        color: #94a3b8;
                        border: 1px solid #cbd5e1;
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #34d399, stop:1 #10b981); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #34d399; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669);
                        border-color: #10b981;
                    }
                    QPushButton:disabled {
                        background: #f1f5f9;
                        color: #94a3b8;
                        border: 1px solid #cbd5e1;
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f87171, stop:1 #ef4444); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f87171; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ef4444, stop:1 #dc2626);
                        border-color: #ef4444;
                    }
                    QPushButton:disabled {
                        background: #f1f5f9;
                        color: #94a3b8;
                        border: 1px solid #cbd5e1;
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: #ffffff; color: #334155; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #cbd5e1;")

        elif self.tema_modu == "Hacker":
            self.setStyleSheet(common + f"""
                QMainWindow {{ background-color: #000000; }} 
                QWidget {{ color: #39ff14; font-family: 'Courier New', monospace; }} 
                QLineEdit {{ background: #000000; color: #39ff14; border: 1px solid #39ff14; border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 2px solid #39ff14; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #003300, stop:1 #007700); 
                    color: #39ff14; 
                    font-weight: bold; 
                    border: 1px solid #39ff14; 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005500, stop:1 #00aa00); 
                    border-color: #39ff14; 
                }} 
                QPushButton:pressed {{
                    background: #39ff14;
                    color: black;
                }}
                QTextBrowser {{ 
                    background: #000000; 
                    color: #39ff14; 
                    border: 1px solid #39ff14; 
                    border-left: 4px solid #39ff14; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: #000000; 
                    color: #39ff14; 
                    border: 1px solid #39ff14; 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005500, stop:1 #00aa00);
                    color: #39ff14;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(57, 255, 20, 0.2);
                    color: #39ff14;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #39ff14; 
                    background: #000000; 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: #000000; 
                    color: #007700; 
                    padding: 8px 16px; 
                    border: 1px solid #39ff14; 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #003300, stop:1 #007700); 
                    color: #39ff14; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: #002200;
                    color: #39ff14;
                }}
                QGroupBox {{ 
                    border: 1px solid #39ff14; 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: #000000;
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #39ff14; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: #000000; 
                    color: #39ff14; 
                    border: 1px solid #39ff14; 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: #000000; 
                    color: #39ff14; 
                    selection-background-color: #39ff14; 
                    selection-color: black;
                    border: 1px solid #39ff14;
                }}
                QMessageBox {{ 
                    background-color: #000000; 
                    border: 1px solid #39ff14;
                }}
                QMessageBox QLabel {{ 
                    color: #39ff14; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #003300, stop:1 #007700); 
                    color: #39ff14; 
                    font-weight: bold;
                    border: 1px solid #39ff14; 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: #000000;
                    color: #39ff14;
                    gridline-color: #00aa00;
                    border: 1px solid #39ff14;
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #39ff14;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005500, stop:1 #00aa00);
                    color: #39ff14;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #000000, stop:1 #003300);
                    color: #39ff14;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid #39ff14;
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005500, stop:1 #39ff14); 
                        color: black; 
                        font-weight: bold; 
                        border: 1px solid #39ff14; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00aa00, stop:1 #39ff14);
                        border-color: #39ff14;
                    }
                    QPushButton:disabled {
                        background: #111111;
                        color: #004400;
                        border: 1px solid #004400;
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #550000, stop:1 #ff0033); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #ff0033; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #aa0000, stop:1 #ff0033);
                        border-color: #ff0033;
                    }
                    QPushButton:disabled {
                        background: #111111;
                        color: #004400;
                        border: 1px solid #004400;
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005500, stop:1 #39ff14); 
                        color: black; 
                        font-weight: bold; 
                        border: 1px solid #39ff14; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00aa00, stop:1 #39ff14);
                        border-color: #39ff14;
                    }
                    QPushButton:disabled {
                        background: #111111;
                        color: #004400;
                        border: 1px solid #004400;
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #550000, stop:1 #ff0033); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #ff0033; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #aa0000, stop:1 #ff0033);
                        border-color: #ff0033;
                    }
                    QPushButton:disabled {
                        background: #111111;
                        color: #004400;
                        border: 1px solid #004400;
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: #000000; color: #39ff14; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #39ff14;")

        elif self.tema_modu == "Nebula":
            self.setStyleSheet(common + f"""
                QMainWindow {{ background-color: #0b0b16; }} 
                QWidget {{ color: #e1e1ff; font-family: 'Segoe UI', sans-serif; }} 
                QLineEdit {{ background: #121226; color: #ff79c6; border: 1px solid #bd93f9; border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 1px solid #ff79c6; background: #181832; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #bd93f9, stop:1 #ff79c6); 
                    color: #0b0b16; 
                    font-weight: bold; 
                    border: 1px solid #bd93f9; 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #a370f7, stop:1 #ff55a3); 
                    border-color: #ff79c6; 
                }} 
                QPushButton:pressed {{
                    background: #8be9fd;
                    color: #0b0b16;
                }}
                QTextBrowser {{ 
                    background: #0d0d1f; 
                    color: #e1e1ff; 
                    border: 1px solid #bd93f9; 
                    border-left: 4px solid #ff79c6; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: #121226; 
                    color: #8be9fd; 
                    border: 1px solid #bd93f9; 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #bd93f9, stop:1 #ff79c6);
                    color: #0b0b16;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(189, 147, 249, 0.2);
                    color: #ff79c6;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #bd93f9; 
                    background: #0b0b16; 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: #121226; 
                    color: #bd93f9; 
                    padding: 8px 16px; 
                    border: 1px solid #22223b; 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #bd93f9, stop:1 #ff79c6); 
                    color: #0b0b16; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: #181832;
                    color: #ff79c6;
                }}
                QGroupBox {{ 
                    border: 1px solid #bd93f9; 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: #0d0d1f;
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #ff79c6; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: #121226; 
                    color: #bd93f9; 
                    border: 1px solid #bd93f9; 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: #121226; 
                    color: #bd93f9; 
                    selection-background-color: #ff79c6; 
                    selection-color: #0b0b16;
                    border: 1px solid #bd93f9;
                }}
                QMessageBox {{ 
                    background-color: #0b0b16; 
                    border: 1px solid #bd93f9;
                }}
                QMessageBox QLabel {{ 
                    color: #e1e1ff; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #bd93f9, stop:1 #ff79c6); 
                    color: #0b0b16; 
                    font-weight: bold;
                    border: 1px solid #bd93f9; 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: #121226;
                    color: #e1e1ff;
                    gridline-color: #bd93f9;
                    border: 1px solid #bd93f9;
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #e1e1ff;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #bd93f9, stop:1 #ff79c6);
                    color: #0b0b16;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #121226, stop:1 #0d0d1f);
                    color: #ff79c6;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid #bd93f9;
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669); 
                        color: #0b0b16; 
                        font-weight: bold; 
                        border: 1px solid #10b981; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
                        border-color: #059669;
                    }
                    QPushButton:disabled {
                        background: #22223b;
                        color: #555555;
                        border: 1px solid #333333;
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f43f5e, stop:1 #e11d48); 
                        color: #0b0b16; 
                        font-weight: bold; 
                        border: 1px solid #f43f5e; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #be123c);
                        border-color: #e11d48;
                    }
                    QPushButton:disabled {
                        background: #22223b;
                        color: #555555;
                        border: 1px solid #333333;
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #059669); 
                        color: #0b0b16; 
                        font-weight: bold; 
                        border: 1px solid #10b981; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #047857);
                        border-color: #059669;
                    }
                    QPushButton:disabled {
                        background: #22223b;
                        color: #555555;
                        border: 1px solid #333333;
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f43f5e, stop:1 #e11d48); 
                        color: #0b0b16; 
                        font-weight: bold; 
                        border: 1px solid #f43f5e; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #be123c);
                        border-color: #e11d48;
                    }
                    QPushButton:disabled {
                        background: #22223b;
                        color: #555555;
                        border: 1px solid #333333;
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: #080814; color: #8be9fd; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #bd93f9;")

        elif self.tema_modu == "Tropik":
            self.setStyleSheet(common + f"""
                QMainWindow {{ background-color: #05201d; }} 
                QWidget {{ color: #d2f5e3; font-family: 'Segoe UI', sans-serif; }} 
                QLineEdit {{ background: #0b332f; color: #02c39a; border: 1px solid #00a896; border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 1px solid #ff9f1c; background: #0e3d38; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #028090, stop:1 #02c39a); 
                    color: white; 
                    font-weight: bold; 
                    border: 1px solid #028090; 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #02c39a, stop:1 #00a896); 
                    border-color: #ff9f1c; 
                }} 
                QPushButton:pressed {{
                    background: #ff9f1c;
                    color: #05201d;
                }}
                QTextBrowser {{ 
                    background: #0b332f; 
                    color: #e2fcf0; 
                    border: 1px solid #00a896; 
                    border-left: 4px solid #02c39a; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: #0b332f; 
                    color: #02c39a; 
                    border: 1px solid #00a896; 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #028090, stop:1 #02c39a);
                    color: white;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(2, 195, 154, 0.2);
                    color: #02c39a;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid #00a896; 
                    background: #05201d; 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: #0b332f; 
                    color: #028090; 
                    padding: 8px 16px; 
                    border: 1px solid #00a896; 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #028090, stop:1 #02c39a); 
                    color: white; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: #0e3d38;
                    color: #ff9f1c;
                }}
                QGroupBox {{ 
                    border: 1px solid #00a896; 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: #0b332f;
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #ff9f1c; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: #0b332f; 
                    color: #02c39a; 
                    border: 1px solid #00a896; 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: #0b332f; 
                    color: #02c39a; 
                    selection-background-color: #02c39a; 
                    selection-color: #05201d;
                    border: 1px solid #00a896;
                }}
                QMessageBox {{ 
                    background-color: #05201d; 
                    border: 1px solid #00a896;
                }}
                QMessageBox QLabel {{ 
                    color: #d2f5e3; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #028090, stop:1 #02c39a); 
                    color: white; 
                    font-weight: bold;
                    border: 1px solid #028090; 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: #0b332f;
                    color: #d2f5e3;
                    gridline-color: #00a896;
                    border: 1px solid #00a896;
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #d2f5e3;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #028090, stop:1 #02c39a);
                    color: white;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0b332f, stop:1 #05201d);
                    color: #02c39a;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid #00a896;
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #02c39a, stop:1 #00a896); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #02c39a; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00a896, stop:1 #028090);
                        border-color: #ff9f1c;
                    }
                    QPushButton:disabled {
                        background: #05201d;
                        color: #0b332f;
                        border: 1px solid #00a896;
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f26419, stop:1 #ff9f1c); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f26419; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff9f1c, stop:1 #f26419);
                        border-color: #02c39a;
                    }
                    QPushButton:disabled {
                        background: #05201d;
                        color: #0b332f;
                        border: 1px solid #00a896;
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #02c39a, stop:1 #00a896); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #02c39a; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00a896, stop:1 #028090);
                        border-color: #ff9f1c;
                    }
                    QPushButton:disabled {
                        background: #05201d;
                        color: #0b332f;
                        border: 1px solid #00a896;
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f26419, stop:1 #ff9f1c); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid #f26419; 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff9f1c, stop:1 #f26419);
                        border-color: #02c39a;
                    }
                    QPushButton:disabled {
                        background: #05201d;
                        color: #0b332f;
                        border: 1px solid #00a896;
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: #05201d; color: #ff9f1c; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #02c39a;")

        elif self.tema_modu == "Mango":
            self.setStyleSheet(common + f"""
                QMainWindow {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f5a623, stop:0.4 #ff6b81, stop:0.8 #badc58, stop:1 #90be6d); 
                }} 
                QWidget {{ color: #2d3748; font-family: 'Segoe UI', sans-serif; }} 
                QLineEdit {{ background: rgba(255, 255, 255, 0.85); color: #2c3e50; border: 1px solid rgba(255, 107, 129, 0.5); border-radius: 5px; padding: 4px; }} 
                QLineEdit:focus {{ border: 2px solid #ff6b81; background: #ffffff; }}
                QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81); 
                    color: white; 
                    font-weight: bold; 
                    border: 1px solid rgba(255, 255, 255, 0.3); 
                    border-radius: 5px; 
                    padding: 6px 12px; 
                }} 
                QPushButton:hover {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6b81, stop:1 #badc58); 
                    border-color: white; 
                }} 
                QPushButton:pressed {{
                    background: #2c3e50;
                    color: white;
                }}
                QTextBrowser {{ 
                    background: rgba(255, 255, 255, 0.88); 
                    color: #2d3748; 
                    border: 1px solid rgba(255, 107, 129, 0.4); 
                    border-left: 4px solid #ff6b81; 
                    border-radius: 6px; 
                }} 
                QListWidget {{ 
                    background: rgba(255, 255, 255, 0.85); 
                    color: #2d3748; 
                    border: 1px solid rgba(255, 107, 129, 0.4); 
                    border-radius: 6px; 
                    padding: 5px;
                }} 
                QListWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81);
                    color: white;
                    font-weight: bold;
                    border-radius: 4px;
                }}
                QListWidget::item:hover {{
                    background-color: rgba(255, 107, 129, 0.1);
                    color: #ff6b81;
                    border-radius: 4px;
                }}
                QTabWidget::pane {{ 
                    border: 1px solid rgba(255, 255, 255, 0.4); 
                    background: rgba(255, 255, 255, 0.75); 
                    border-radius: 6px;
                }} 
                QTabBar::tab {{ 
                    background: rgba(255, 255, 255, 0.6); 
                    color: #2d3748; 
                    padding: 8px 16px; 
                    border: 1px solid rgba(255, 255, 255, 0.4); 
                    border-bottom: none; 
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px;
                    margin-right: 4px;
                }} 
                QTabBar::tab:selected {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81); 
                    color: white; 
                    font-weight: bold;
                }} 
                QTabBar::tab:hover {{
                    background: rgba(255, 255, 255, 0.95);
                    color: #ff6b81;
                }}
                QGroupBox {{ 
                    border: 1px solid rgba(255, 107, 129, 0.4); 
                    border-radius: 8px;
                    margin-top: 15px; 
                    padding: 15px; 
                    background: rgba(255, 255, 255, 0.85);
                }} 
                QGroupBox::title {{ 
                    subcontrol-origin: margin; 
                    left: 15px; 
                    color: #ff6b81; 
                    font-weight: bold;
                }}
                QComboBox {{ 
                    background: rgba(255, 255, 255, 0.9); 
                    color: #2d3748; 
                    border: 1px solid rgba(255, 107, 129, 0.4); 
                    border-radius: 5px;
                    padding: 4px 8px; 
                }}
                QComboBox QAbstractItemView {{ 
                    background: white; 
                    color: #2d3748; 
                    selection-background-color: #ff6b81; 
                    selection-color: white;
                    border: 1px solid rgba(255, 107, 129, 0.4);
                }}
                QMessageBox {{ 
                    background-color: rgba(255, 255, 255, 0.95); 
                    border: 1px solid #ff6b81;
                }}
                QMessageBox QLabel {{ 
                    color: #2d3748; 
                }}
                QMessageBox QPushButton {{ 
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81); 
                    color: white; 
                    font-weight: bold;
                    border: 1px solid rgba(255, 255, 255, 0.3); 
                    border-radius: 4px;
                    padding: 5px 15px; 
                    min-width: 80px; 
                }}
                QTableWidget {{
                    background: rgba(255, 255, 255, 0.85);
                    color: #2d3748;
                    gridline-color: rgba(255, 107, 129, 0.2);
                    border: 1px solid rgba(255, 107, 129, 0.4);
                    border-radius: 6px;
                }}
                QTableWidget::item {{
                    color: #2d3748;
                }}
                QTableWidget::item:selected {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81);
                    color: white;
                }}
                QHeaderView::section {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f5a623, stop:1 #ff6b81);
                    color: white;
                    font-weight: bold;
                    padding: 4px;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }}
            """)
            
            # DPI ve DoS Butonlarını ve Log ekranını stilize et
            if hasattr(self, 'btn_dpi_start') and hasattr(self, 'btn_dpi_stop'):
                self.btn_dpi_start.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6b81, stop:1 #badc58); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid rgba(255, 255, 255, 0.3); 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #badc58, stop:1 #90be6d);
                        border-color: white;
                    }
                    QPushButton:disabled {
                        background: rgba(255, 255, 255, 0.3);
                        color: rgba(45, 55, 72, 0.5);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                """)
                self.btn_dpi_stop.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #ff6b81); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid rgba(255, 255, 255, 0.3); 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6b81, stop:1 #e11d48);
                        border-color: white;
                    }
                    QPushButton:disabled {
                        background: rgba(255, 255, 255, 0.3);
                        color: rgba(45, 55, 72, 0.5);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                """)
            if hasattr(self, 'dos_btn_baslat') and hasattr(self, 'dos_btn_durdur'):
                self.dos_btn_baslat.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6b81, stop:1 #badc58); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid rgba(255, 255, 255, 0.3); 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #badc58, stop:1 #90be6d);
                        border-color: white;
                    }
                    QPushButton:disabled {
                        background: rgba(255, 255, 255, 0.3);
                        color: rgba(45, 55, 72, 0.5);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                """)
                self.dos_btn_durdur.setStyleSheet("""
                    QPushButton {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e11d48, stop:1 #ff6b81); 
                        color: white; 
                        font-weight: bold; 
                        border: 1px solid rgba(255, 255, 255, 0.3); 
                        border-radius: 6px;
                    }
                    QPushButton:hover {
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff6b81, stop:1 #e11d48);
                        border-color: white;
                    }
                    QPushButton:disabled {
                        background: rgba(255, 255, 255, 0.3);
                        color: rgba(45, 55, 72, 0.5);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                """)
            if hasattr(self, 'dos_log_ekrani'):
                self.dos_log_ekrani.setStyleSheet("background: rgba(20, 30, 25, 0.9); color: #ffd175; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #ff6b81;")

        # İstatistik Kartlarının arka planını dinamik güncelle
        if hasattr(self, 'dos_stat_acik') and hasattr(self, 'dos_stat_kapali') and hasattr(self, 'dos_stat_toplam'):
            bg = "#ffffff" if self.tema_modu == "Aydınlık" else "#111122" if self.tema_modu == "Nebula" else "#0b332f" if self.tema_modu == "Tropik" else "rgba(255, 255, 255, 0.85)" if self.tema_modu == "Mango" else "#1e293b" if self.tema_modu == "Karanlık" else "#000000"
            self.dos_stat_acik.setStyleSheet(f"QFrame {{ background:{bg}; border:1px solid #06d6a0; border-radius:6px; padding:6px; }}")
            self.dos_stat_kapali.setStyleSheet(f"QFrame {{ background:{bg}; border:1px solid #ff6b35; border-radius:6px; padding:6px; }}")
            self.dos_stat_toplam.setStyleSheet(f"QFrame {{ background:{bg}; border:1px solid #4ecdc4; border-radius:6px; padding:6px; }}")

        # Durum etiketini temaya göre renklendir
        if hasattr(self, 'dos_durum_label'):
            color = "#39ff14" if self.tema_modu == "Hacker" else "#ff79c6" if self.tema_modu == "Nebula" else "#02c39a" if self.tema_modu == "Tropik" else "#ff6b81" if self.tema_modu == "Mango" else "#2563eb" if self.tema_modu == "Aydınlık" else "#38bdf8"
            self.dos_durum_label.setStyleSheet(f"color:{color}; font-size:12px; padding:2px; font-weight:bold;")

        # Eğitsel Rehber HTML'ini temaya göre güncelle
        try:
            if hasattr(self, 'dos_rehber_browser'):
                self.dos_rehber_browser.setHtml(self._dos_rehber_html())
            if hasattr(self, 'rev_rehber_browser'):
                self.rev_rehber_browser.setHtml(self._rev_rehber_html())
        except:
            pass

    def wiki_sekmesi_olustur(self):
        duzen = QHBoxLayout()
        sol = QVBoxLayout()
        self.arama = QLineEdit(); self.arama.setPlaceholderText("Ara (Ctrl+F)...")
        self.arama.textChanged.connect(self.filtrele)
        self.liste = QListWidget(); self.liste.currentTextChanged.connect(self.goster)
        sol.addWidget(self.arama); sol.addWidget(self.liste)
        
        self.btn_pdf = QPushButton("📄 PDF Rapor Oluştur")
        self.btn_pdf.clicked.connect(self.export_pdf)
        sol.addWidget(self.btn_pdf)

        self.ekran = QTextBrowser()
        duzen.addLayout(sol, 1); duzen.addWidget(self.ekran, 2)
        self.wiki_sekmesi.setLayout(duzen)

    def araclar_sekmesi_olustur(self):
        # Mevcut araçlar yapını koruyarak daha düzenli hale getirdim
        duzen = QHBoxLayout()
        sol = QVBoxLayout()
        
        self.arac_sonuc_ekrani = QTextBrowser()
        
        # IP Aracı
        sol.addWidget(QLabel("<b>IP & Whois Araçları</b>"))
        self.ip_input_arac = QLineEdit(); self.ip_input_arac.setPlaceholderText("IP/Domain girin")
        btn_ip = QPushButton("Sorgula"); btn_ip.clicked.connect(self.arac_ip_bul)
        btn_kendi_ip = QPushButton("Kendi IP'mi Bul"); btn_kendi_ip.clicked.connect(self.arac_kendi_ip)
        sol.addWidget(self.ip_input_arac); sol.addWidget(btn_ip); sol.addWidget(btn_kendi_ip)
        
        # Port Tarayıcı
        sol.addWidget(QLabel("<br><b>Port Tarayıcı</b>"))
        self.port_input = QLineEdit(); self.port_input.setPlaceholderText("Hedef IP")
        btn_port = QPushButton("Tara"); btn_port.clicked.connect(self.arac_port_tara)
        sol.addWidget(self.port_input); sol.addWidget(btn_port)

        # --- Web Zafiyet Tarayıcı Arayüzü ---
        sol.addWidget(QLabel("<br><b>Web Zafiyet Tarayıcı (SQLi & XSS)</b>"))
        self.web_zap_input = QLineEdit()
        self.web_zap_input.setPlaceholderText("Hedef URL girin (Örn: http://testphp.vulnweb.com/)")
        btn_web_tara = QPushButton("Zafiyet Taraması Başlat")
        btn_web_tara.clicked.connect(self.arac_web_zafiyet_tara)
        sol.addWidget(self.web_zap_input)
        sol.addWidget(btn_web_tara)
        
        # Dosya Analizi
        sol.addWidget(QLabel("<br><b>VirusTotal Dosya Analizi</b>"))
        btn_dosya_sec = QPushButton("Dosya Seç ve Tara")
        btn_dosya_sec.clicked.connect(self.arac_dosya_analiz)
        sol.addWidget(btn_dosya_sec)
        
        # Crypto
        sol.addWidget(QLabel("<br><b>Kripto & Şifre</b>"))
        self.hash_input = QLineEdit(); self.hash_input.setPlaceholderText("Metin")
        btn_h = QPushButton("Hash Üret"); btn_h.clicked.connect(self.arac_hash_uret)
        btn_p = QPushButton("Güçlü Şifre Üret"); btn_p.clicked.connect(self.arac_sifre_uret)
        
        self.hash_kir_input = QLineEdit(); self.hash_kir_input.setPlaceholderText("Kırılacak MD5 Hash")
        btn_hk = QPushButton("Hash Kır (Brute Force)"); btn_hk.clicked.connect(self.arac_hash_kir)
        
        sol.addWidget(self.hash_input); sol.addWidget(btn_h); sol.addWidget(btn_p)
        sol.addWidget(self.hash_kir_input); sol.addWidget(btn_hk)
        
        sol.addStretch()
        duzen.addLayout(sol, 1); duzen.addWidget(self.arac_sonuc_ekrani, 2)
        self.araclar_sekmesi.setLayout(duzen)

    # --- DİĞER FONKSİYONLAR (ip_bul, hash_uret, port_tara vb.) AYNI ŞEKİLDE KORUNACAK ---
    # (Kodun geri kalanı mevcut kodunla aynı, sadece yeni sekmeyi ekledim)
    
    def verileri_yukle(self, filtre=""):
        self.liste.clear()
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        if filtre: cur.execute("SELECT baslik FROM wiki WHERE baslik LIKE ?", ('%'+filtre+'%',))
        else: cur.execute("SELECT baslik FROM wiki")
        for s in cur.fetchall(): self.liste.addItem(s[0])
        conn.close()

    def goster(self, baslik):
        if not baslik: return
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        cur.execute("SELECT icerik FROM wiki WHERE baslik = ?", (baslik,))
        res = cur.fetchone(); conn.close()
        if res: self.ekran.setHtml(res[0])

    def filtrele(self, metin): self.verileri_yukle(metin)

    def export_pdf(self):
        baslik = self.liste.currentItem().text() if self.liste.currentItem() else "Rapor"
        gecersiz = [":", "/", "\\", "*", "?", "\"", "<", ">", "|"]
        temiz_baslik = "".join([c if c not in gecersiz else "-" for c in baslik])
        
        filename, _ = QFileDialog.getSaveFileName(self, "PDF Olarak Kaydet", f"{temiz_baslik}.pdf", "PDF Files (*.pdf)")
        if not filename: return
        
        try:
            # Belgeyi klonla (ekrandaki görünümü bozmamak için)
            doc = self.ekran.document().clone()
            
            # PDF için font boyutunu ve stilini ayarla
            font = doc.defaultFont()
            font.setPointSize(16) 
            doc.setDefaultFont(font)
            
            # Sayfa Düzeni (A4, Kenar boşlukları: 20mm)
            layout = QPageLayout(
                QPageSize(QPageSize.PageSizeId.A4),
                QPageLayout.Orientation.Portrait,
                QMarginsF(20, 20, 20, 20)
            )
            
            if hasattr(doc, 'printToPdf'):
                doc.printToPdf(filename, layout)
            elif QPrinter is not None:
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setPageLayout(layout)
                printer.setOutputFileName(filename)
                doc.print(printer)
            else:
                raise Exception("PDF modülü eksik.")
                
            QMessageBox.information(self, "Başarılı", f"'{baslik}' kaydedildi.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"PDF Hatası: {str(e)}")

    # ... Buraya diğer araç fonksiyonlarını (arac_ip_bul, arac_hash_uret vb.) mevcut kodundan kopyalayıp koyabilirsin.

    def ayarlar_sekmesi_olustur(self):
        main_layout = QVBoxLayout()
        
        # 1. Görünüm Özelleştirme
        v_group = QGroupBox("🎨 Görünüm ve Tema")
        v_layout = QFormLayout()
        self.tema_kutu = QComboBox(); self.tema_kutu.addItems(["Karanlık", "Aydınlık", "Hacker", "Nebula", "Tropik", "Mango"])
        self.tema_kutu.setCurrentText(self.tema_modu)
        self.tema_kutu.currentIndexChanged.connect(self.ayarlar_tema_degistir)
        self.font_ayar = QSpinBox(); self.font_ayar.setRange(10, 24); self.font_ayar.setValue(self.font_size)
        self.font_ayar.valueChanged.connect(self.ayarlar_font_degistir)
        v_layout.addRow("Tema Seçimi:", self.tema_kutu)
        v_layout.addRow("Yazı Boyutu:", self.font_ayar)
        v_group.setLayout(v_layout)
        main_layout.addWidget(v_group)

        # 2. Veritabanı Bakımı
        db_group = QGroupBox("💾 Veritabanı ve Yedekleme")
        db_layout = QHBoxLayout()
        btn_backup = QPushButton("Yedek Oluştur"); btn_backup.clicked.connect(self.db_yedekle)
        btn_export = QPushButton("JSON Dışa Aktar"); btn_export.clicked.connect(self.db_export_json)
        btn_reset = QPushButton("Sıfırla"); btn_reset.clicked.connect(self.db_sifirla)
        db_layout.addWidget(btn_backup); db_layout.addWidget(btn_export); db_layout.addWidget(btn_reset)
        db_group.setLayout(db_layout)
        main_layout.addWidget(db_group)
        
        main_layout.addStretch()
        self.ayarlar_sekmesi.setLayout(main_layout)

    def ayarlar_tema_degistir(self, i):
        self.tema_modu = self.tema_kutu.currentText()
        self.tema_uygula()
        try:
            conn = sqlite3.connect(DB_FILE)
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO settings (anahtar, deger) VALUES ('tema', ?)", (self.tema_modu,))
            conn.commit()
            conn.close()
        except: pass

    def ayarlar_font_degistir(self, v):
        self.font_size = v
        self.tema_uygula()



    def bulut_anahtarlari_yukle(self):
        """Bulut üzerinden yedek/ortak API anahtarlarını arka planda çekerek yükler."""
        def fetch():
            try:
                resp = requests.get(MASTER_KEYS_URL, timeout=5)
                if resp.status_code == 200:
                    cloud_keys = resp.json()
                    for k, v in cloud_keys.items():
                        if v and not v.startswith("BURAYA_"):
                            self.master_keys[k] = v
            except: pass
        
        # Basit bir thread başlat
        t = QThread()
        t.run = fetch
        t.start()
        self.track_thread(t)

    def db_yedekle(self):
        try:
            shutil.copy(DB_FILE, f"{DB_FILE}.bak")
            QMessageBox.information(self, "Yedekleme", "Veritabanı yedeği (siber_wiki.db.bak) oluşturuldu.")
        except Exception as e: QMessageBox.critical(self, "Hata", str(e))

    def db_export_json(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Dışa Aktar", "wiki_data.json", "JSON Files (*.json)")
        if filename:
            conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
            cur.execute("SELECT baslik, icerik FROM wiki")
            data = [{"baslik": b, "icerik": i} for b, i in cur.fetchall()]
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            conn.close()
            QMessageBox.information(self, "Başarılı", "Veriler JSON olarak dışa aktarıldı.")

    def db_sifirla(self):
        onay = QMessageBox.question(self, "Dikkat", "Veritabanı sıfırlanacak. Emin misiniz?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if onay == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
            cur.execute("DELETE FROM wiki")
            conn.commit(); conn.close()
            init_db(); self.verileri_yukle()
            QMessageBox.information(self, "Bilgi", "Veritabanı sıfırlandı ve varsayılanlar yüklendi.")
    def arac_ip_goster(self, response, ip):
        if response.get('status') == 'success':
            harita_url = f"https://static-maps.yandex.ru/1.x/?ll={response['lon']},{response['lat']}&z=10&l=map&size=400,200&pt={response['lon']},{response['lat']},pm2rdm"
            sonuc = f"""
            <h2>IP Tespit Sonucu: {ip}</h2>
            <img src="{harita_url}" width="400" height="200" alt="Harita Yüklenemedi" />
            <br><br>
            <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width:100%;">
                <tr><td><b>Ülke:</b></td><td>{response.get('country', '-')}</td></tr>
                <tr><td><b>Şehir:</b></td><td>{response.get('city', '-')}</td></tr>
                <tr><td><b>ISP:</b></td><td>{response.get('isp', '-')}</td></tr>
                <tr><td><b>Organizasyon:</b></td><td>{response.get('org', '-')}</td></tr>
                <tr><td><b>Enlem/Boylam:</b></td><td>{response.get('lat', '-')} / {response.get('lon', '-')}</td></tr>
            </table>
            """
            self.arac_sonuc_ekrani.setHtml(sonuc)
        else:
            self.arac_sonuc_ekrani.setHtml("<h2 style='color:red'>Hata: Geçersiz IP adresi veya API sınırı!</h2>")

    def arac_ip_bul(self):
        ip = self.ip_input_arac.text().strip()
        if not ip: return
        self.arac_sonuc_ekrani.setHtml("<i>Sorgulanıyor... Lütfen bekleyin.</i>")
        
        self.network_worker = NetworkWorkerThread(ip)
        self.track_thread(self.network_worker)
        self.network_worker.sonuc_sinyali.connect(self.arac_ip_goster)
        self.network_worker.hata_sinyali.connect(lambda e: self.arac_sonuc_ekrani.setHtml(f"<h2 style='color:red'>Bağlantı Hatası!</h2><p>{e}</p>"))
        self.network_worker.start()

    def arac_kendi_ip(self):
        self.arac_sonuc_ekrani.setHtml("<i>Kendi IP'niz bulunuyor...</i>")
        
        self.network_worker = NetworkWorkerThread() # target_ip=None for own IP
        self.track_thread(self.network_worker)
        self.network_worker.sonuc_sinyali.connect(self.arac_ip_goster)
        self.network_worker.hata_sinyali.connect(lambda e: self.arac_sonuc_ekrani.setHtml(f"<h2 style='color:red'>Bağlantı Hatası!</h2><p>{e}</p>"))
        self.network_worker.start()

    def arac_hash_uret(self):
        metin = self.hash_input.text()
        if not metin:
            self.arac_sonuc_ekrani.setHtml("<h2 style='color:red'>Lütfen metin girin.</h2>")
            return
        self.session_words.add(metin) # Seans belleğine ekle
        md5_h = hashlib.md5(metin.encode()).hexdigest()
        sha1_h = hashlib.sha1(metin.encode()).hexdigest()
        sha256_h = hashlib.sha256(metin.encode()).hexdigest()
        sonuc = f"<h2>Hash Sonuçları</h2><p><b>Girdi:</b> {metin}</p><hr><p><b>MD5:</b> {md5_h}</p><p><b>SHA-1:</b> {sha1_h}</p><p><b>SHA-256:</b> {sha256_h}</p>"
        self.arac_sonuc_ekrani.setHtml(sonuc)

    def arac_sifre_uret(self):
        karakterler = string.ascii_letters + string.digits + "!@#$%^&*()"
        sifre = ''.join(random.choice(karakterler) for i in range(16))
        sonuc = f"<h2>Güçlü Şifre</h2><p>Üretilen 16 haneli güvenli şifre:</p><h3 style='background:#222; padding:10px; border:1px solid #555;'>{sifre}</h3>"
        self.arac_sonuc_ekrani.setHtml(sonuc)

    def arac_hash_kir(self):
        target = self.hash_kir_input.text().strip().lower()
        if not target: return
        
        # 1. Seans Belleği (O an yazılan kelimeler)
        for word in self.session_words:
            if hashlib.md5(word.encode()).hexdigest() == target:
                self.arac_sonuc_ekrani.setHtml(f"<h2>Hash Kırıldı (Seans Belleği)</h2><p style='color:#00ff00'><b>Bulunan:</b> {word}</p>")
                return

        # 2. Yerel Wordlist
        wordlist = ["123456", "password", "12345678", "qwerty", "admin", "welcome", "siber", "güvenlik", "12345", "123", "root", "123456789", "merhaba"]
        for word in wordlist:
            if hashlib.md5(word.encode()).hexdigest() == target:
                self.arac_sonuc_ekrani.setHtml(f"<h2>Hash Kırıldı (Yerel Liste)</h2><p style='color:#00ff00'><b>Bulunan:</b> {word}</p>")
                return

        # 3. Online Sorgu
        self.arac_sonuc_ekrani.setHtml("<i>Offline kırılamadı, Online Veritabanı sorgulanıyor...</i>")
        QApplication.processEvents()
        try:
            # Ücretsiz MD5 lookup servisi
            resp = requests.get(f"https://nitrxgen.net/md5db/{target}", timeout=5)
            if resp.status_code == 200 and resp.text:
                self.arac_sonuc_ekrani.setHtml(f"<h2>Hash Kırıldı (Online İstihbarat)</h2><p style='color:#00ff00'><b>Bulunan:</b> {resp.text}</p>")
                return
        except: pass
        
        self.arac_sonuc_ekrani.setHtml("<h2>Hash Kırılamadı</h2><p style='color:red'>Hiçbir kaynakta eşleşme bulunamadı.</p>")

    def arac_port_tara(self):
        ip = self.port_input.text()
        if not ip:
            self.arac_sonuc_ekrani.setHtml("<h2 style='color:red'>Hedef IP girin.</h2>")
            return
        self.arac_sonuc_ekrani.setHtml(f"<i>{ip} taranıyor...</i>")
        self.tarayici_thread = PortScannerThread(ip)
        self.track_thread(self.tarayici_thread)
        self.tarayici_thread.sonuc_sinyali.connect(self.arac_port_tarama_bitti)
        self.tarayici_thread.start()

    def arac_port_tarama_bitti(self, sonuc_html):
        self.arac_sonuc_ekrani.setHtml(sonuc_html)

    def arac_web_zafiyet_tara(self):
        url = self.web_zap_input.text()
        if not url:
            self.arac_sonuc_ekrani.setHtml("<h2 style='color:red'>Lütfen geçerli bir hedef URL girin.</h2>")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        self.arac_sonuc_ekrani.setHtml(f"<i>{url} adresi XSS ve SQLi risklerine karşı taranıyor... Lütfen bekleyin.</i>")
        QApplication.processEvents() # Arayüzün donmaması için anlık güncelliyoruz

        try:
            scanner = WebScannerEngine(url)
            xss_sonuc = scanner.scan_xss()
            sqli_sonuc = scanner.scan_sqli()

            rapor = f"""
            <h2>🛡️ Web Zafiyet Tarama Raporu</h2>
            <hr>
            {xss_sonuc}
            {sqli_sonuc}
            """
            self.arac_sonuc_ekrani.setHtml(rapor)
        except Exception as e:
            self.arac_sonuc_ekrani.setHtml(f"<h2 style='color:red'>Tarama sırasında bir hata oluştu: {str(e)}</h2>")

    def arac_dosya_analiz(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Analiz İçin Dosya Seç", "", "All Files (*)")
        if not file_path: return

        # API Anahtarını al (Yoksa bile arka plan modülü kendi havuzunu ve MalwareBazaar'ı kullanacak)
        conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
        cur.execute("SELECT deger FROM settings WHERE anahtar = 'vt'")
        res = cur.fetchone(); conn.close()
        
        api_key = res[0] if res and res[0] else ""
        if not api_key:
            api_key = self.master_keys.get("vt", "")

        self.arac_sonuc_ekrani.setHtml(f"<i>{file_path} analiz ediliyor...<br><b>Lütfen bekleyin, hızlı tehdit veritabanı taraması ve derinlemesine sandbox analizi yapılıyor.</b></i>")
        
        # Thread başlat (Arayüzün donmaması için)
        self.dosya_thread = FileAnalyzerThread(api_key, file_path)
        self.track_thread(self.dosya_thread)
        self.dosya_thread.sonuc_sinyali.connect(self.arac_dosya_analiz_bitti)
        self.dosya_thread.start()

    def arac_dosya_analiz_bitti(self, rapor_html):
        self.arac_sonuc_ekrani.setHtml(f"<h2>🛡️ Dosya Analiz Raporu</h2><hr>{rapor_html}")

    def dpi_sekmesi_olustur(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        info_label = QLabel("<h2>🔓 DPI Bypass Kontrol Paneli</h2><p>DPI (Deep Packet Inspection) engellemesini aşarak internet üzerindeki kısıtlamaları kaldırın.</p>")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        mode_group = QGroupBox("⚙️ Bypass Ayarları")
        mode_layout = QVBoxLayout()
        info_txt = QLabel("Bu sistem GoodbyeDPI motorunu kullanarak internet paketlerini sürücü seviyesinde düzenler ve tüm engelleri kaldırır.")
        info_txt.setWordWrap(True)
        mode_layout.addWidget(info_txt)
        
        status_info = QLabel("<br><b>Mod:</b> Superonline & Genel (Stabil)<br><b>Yöntem:</b> Kernel-Level Packet Interception")
        mode_layout.addWidget(status_info)
        
        mode_group.setLayout(mode_layout)



        layout.addWidget(mode_group)
        
        btn_layout = QHBoxLayout()
        self.btn_dpi_start = QPushButton("🚀 Bypass Başlat")
        self.btn_dpi_start.clicked.connect(self.arac_dpi_baslat)
        self.btn_dpi_start.setFixedHeight(50)
        
        self.btn_dpi_stop = QPushButton("🛑 Bypass Durdur")
        self.btn_dpi_stop.clicked.connect(self.arac_dpi_durdur)
        self.btn_dpi_stop.setFixedHeight(50)
        self.btn_dpi_stop.setEnabled(False)
        
        btn_layout.addWidget(self.btn_dpi_start)
        btn_layout.addWidget(self.btn_dpi_stop)
        layout.addLayout(btn_layout)
        
        self.dpi_status_label = QLabel("<b>Durum:</b> <span style='color:orange;'>Bekleniyor</span>")
        layout.addWidget(self.dpi_status_label)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def arac_dpi_baslat(self):
        success, message = self.dpi_manager.start_bypass()


        if success:
            self.dpi_status_label.setText(f"<b>Durum:</b> <span style='color:#00ff00;'>{message}</span>")
            self.btn_dpi_start.setEnabled(False)
            self.btn_dpi_stop.setEnabled(True)
            QMessageBox.information(self, "Bilgi", message)
        else:
            self.dpi_status_label.setText(f"<b>Durum:</b> <span style='color:red;'>{message}</span>")
            QMessageBox.critical(self, "Hata", message)

    def arac_dpi_durdur(self):
        success, message = self.dpi_manager.stop_bypass()
        if success:
            self.dpi_status_label.setText(f"<b>Durum:</b> <span style='color:white;'>{message}</span>")
            self.btn_dpi_start.setEnabled(True)
            self.btn_dpi_stop.setEnabled(False)
            QMessageBox.information(self, "Bilgi", message)
        else:
            self.dpi_status_label.setText(f"<b>Durum:</b> <span style='color:red;'>{message}</span>")
            QMessageBox.warning(self, "Uyarı", message)


    # ═══════════════════════════════════════════════════════════════
    # DoS LAB SEKMESİ
    # ═══════════════════════════════════════════════════════════════

    def dos_sekmesi_olustur(self) -> QWidget:
        """⚠️ DoS Lab sekmesini oluşturur: Rehber + Simülatör iç sekmeleri."""
        ana_widget = QWidget()
        ana_layout = QVBoxLayout(ana_widget)
        ana_layout.setContentsMargins(0, 0, 0, 0)

        ic_sekmeler = QTabWidget()
        ic_sekmeler.addTab(self._dos_rehber_olustur(), "📖 Eğitsel Rehber")
        ic_sekmeler.addTab(self._dos_sim_olustur(),    "🧪 Simülatör")

        ana_layout.addWidget(ic_sekmeler)
        return ana_widget

    # ── Eğitsel Rehber ────────────────────────────────────────────

    def _dos_rehber_olustur(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self.dos_rehber_browser = QTextBrowser()
        self.dos_rehber_browser.setOpenExternalLinks(True)
        self.dos_rehber_browser.setHtml(self._dos_rehber_html())
        layout.addWidget(self.dos_rehber_browser)
        return w

    def _dos_rehber_html(self) -> str:
        # Temaya göre renkleri dinamik belirle
        if self.tema_modu == "Nebula":
            bg_color = "#0d0d1f"
            card_bg = "#121226"
            text_color = "#e1e1ff"
            accent_color = "#ff79c6"
            badge_bg = "#bd93f9"
            badge_text = "#0b0b16"
            border_color = "#bd93f9"
        elif self.tema_modu == "Hacker":
            bg_color = "#000000"
            card_bg = "#050905"
            text_color = "#39ff14"
            accent_color = "#39ff14"
            badge_bg = "#00aa00"
            badge_text = "#000000"
            border_color = "#39ff14"
        elif self.tema_modu == "Aydınlık":
            bg_color = "#f8fafc"
            card_bg = "#ffffff"
            text_color = "#0f172a"
            accent_color = "#2563eb"
            badge_bg = "#3b82f6"
            badge_text = "#ffffff"
            border_color = "#cbd5e1"
        elif self.tema_modu == "Tropik":
            bg_color = "#05201d"
            card_bg = "#0b332f"
            text_color = "#d2f5e3"
            accent_color = "#02c39a"
            badge_bg = "#ff9f1c"
            badge_text = "#05201d"
            border_color = "#00a896"
        elif self.tema_modu == "Mango":
            bg_color = "#fff8f0"
            card_bg = "#ffffff"
            text_color = "#2d3748"
            accent_color = "#ff6b81"
            badge_bg = "#badc58"
            badge_text = "#2d3748"
            border_color = "#ff6b81"
        else: # Karanlık (Midnight Slate)
            bg_color = "#0f172a"
            card_bg = "#1e293b"
            text_color = "#f1f5f9"
            accent_color = "#38bdf8"
            badge_bg = "#0284c7"
            badge_text = "#ffffff"
            border_color = "#334155"

        html_tpl = """
<!DOCTYPE html>
<html>
<head>
<style>
  body {
    background: {BG_COLOR};
    color: {TEXT_COLOR};
    font-family: 'Segoe UI', -apple-system, sans-serif;
    font-size: 12.5px;
    padding: 8px;
    margin: 0;
  }
  .warn-banner {
    background: rgba(255, 68, 68, 0.08);
    border: 1px solid #ff4444;
    border-radius: 6px;
    padding: 10px;
    margin-bottom: 12px;
    color: #ff8888;
    font-size: 11px;
  }
  .card {
    background: {CARD_BG};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 10px;
  }
  .card-header {
    font-size: 14px;
    font-weight: bold;
    color: {ACCENT_COLOR};
    border-bottom: 1px solid {BORDER_COLOR};
    padding-bottom: 5px;
    margin-bottom: 8px;
  }
  .title-l7 { color: {ACCENT_COLOR}; }
  .title-l4 { color: {ACCENT_COLOR}; }
  
  .badge {
    display: inline-block;
    font-size: 9px;
    font-weight: bold;
    padding: 1px 5px;
    border-radius: 3px;
    margin-right: 4px;
  }
  .badge-l7 { background: {BADGE_BG}; color: {BADGE_TEXT}; }
  .badge-l4 { background: {BADGE_BG}; color: {BADGE_TEXT}; }
  .badge-green { background: #06d6a0; color: #000; }

  .sub-title {
    color: #06d6a0;
    font-weight: bold;
    margin-top: 8px;
    margin-bottom: 4px;
  }
  .sub-title-warn {
    color: #ff6b35;
    font-weight: bold;
    margin-top: 8px;
    margin-bottom: 4px;
  }
  ul {
    margin: 0;
    padding-left: 15px;
  }
  li {
    margin-bottom: 3px;
    line-height: 1.4;
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 4px;
  }
  th {
    background: {ACCENT_COLOR};
    color: {BADGE_TEXT};
    font-weight: bold;
    padding: 6px 8px;
    text-align: left;
    font-size: 11px;
  }
  td {
    padding: 6px 8px;
    border-bottom: 1px solid {BORDER_COLOR};
    font-size: 11px;
  }
  tr:nth-child(even) td {
    background: rgba(255, 255, 255, 0.02);
  }
</style>
</head>
<body>

<div class="warn-banner">
  <b>🔒 ETİK UYARI:</b> Bu rehber sadece eğitim ve yerel savunma testleri içindir. Yetkisiz saldırı gerçekleştirmek yasal suçtur!
</div>

<!-- KART 1: Özet Tablo -->
<div class="card">
  <div class="card-header">⚙️ Saldırı Türleri Özeti</div>
  <table>
    <tr style="background:#ff6b35; color:#000;">
      <th style="padding:6px;">Saldırı</th>
      <th style="padding:6px;">Katman</th>
      <th style="padding:6px;">Yöntem</th>
      <th style="padding:6px;">Hedef</th>
    </tr>
    <tr>
      <td><b>Slowloris</b></td>
      <td>L7 (Uygulama)</td>
      <td>Yavaş & Eksik İstek</td>
      <td>Bağlantı Kanalları</td>
    </tr>
    <tr>
      <td><b>SYN Flood</b></td>
      <td>L4 (Taşıma)</td>
      <td>Sahte IP & Boş İstek</td>
      <td>Sunucu Belleği</td>
    </tr>
    <tr>
      <td><b>UDP Flood</b></td>
      <td>L4 (Taşıma)</td>
      <td>Yoğun Veri Yağmuru</td>
      <td>Ağ Bant Genişliği</td>
    </tr>
  </table>
</div>

<!-- KART 2: Slowloris -->
<div class="card">
  <div class="card-header title-l7">
    <span class="badge badge-l7">L7</span> <span class="badge badge-green">Düşük Trafik</span> 🐢 Slowloris
  </div>
  
  <div class="sub-title">🎯 Amaç:</div>
  <p style="margin:2px 0 6px 0;">Sunucunun kapılarını (bağlantı havuzunu) kilitler, gerçek kullanıcıların girmesini engeller.</p>
  
  <div class="sub-title">💡 Çalışma Mantığı:</div>
  <ul>
    <li>🚪 Sunucuya çok sayıda TCP bağlantısı açar.</li>
    <li>⏳ Yarım HTTP isteği gönderir ve asla tamamlamaz.</li>
    <li>🫁 Zaman aşımına uğramamak için 10 saniyede bir ufak veri yollayarak bağlantıyı açık tutar.</li>
  </ul>
  
  <div class="sub-title-warn">🛡️ Nasıl Engellenir? (Savunma):</div>
  <ul>
    <li>⚡ <b>Nginx veya Cloudflare</b> gibi asenkron (event-driven) yapılar kullanmak.</li>
    <li>⏱️ Sunucudaki <b>bağlantı zaman aşımı (timeout)</b> sürelerini kısaltmak.</li>
  </ul>
</div>

<!-- KART 3: SYN Flood -->
<div class="card">
  <div class="card-header title-l4">
    <span class="badge badge-l4">L4</span> <span class="badge badge-green">Yarım El Sıkışma</span> 🌊 SYN Flood
  </div>
  
  <div class="sub-title">🎯 Amaç:</div>
  <p style="margin:2px 0 6px 0;">Sunucuya sahte bağlantı istekleri yağdırarak sunucunun işlemcisini ve hafızasını dondurur.</p>
  
  <div class="sub-title">💡 Çalışma Mantığı:</div>
  <ul>
    <li>📨 Sunucuya sahte IP'ler üzerinden yoğun bağlantı istekleri (<code>SYN</code>) yollanır.</li>
    <li>🤝 Sunucu cevap verir (<code>SYN-ACK</code>) ama onay (<code>ACK</code>) paketini sonsuza kadar bekler.</li>
    <li>🗄️ Sunucu bellek tablosundaki (backlog) kuyruk dolar, yeni yasal istekleri kabul edemez.</li>
  </ul>
  
  <div class="sub-title-warn">🛡️ Nasıl Engellenir? (Savunma):</div>
  <ul>
    <li>🍪 Sistemde <b>SYN Cookies</b> (çerez doğrulama) özelliğini aktif etmek.</li>
    <li>📶 Güvenlik duvarı (Firewall) üzerinden IP başına saniyelik limitler (<b>Rate limiting</b>) koymak.</li>
  </ul>
</div>

<!-- KART 4: Sertifikalar -->
<div class="card">
  <div class="card-header">📚 Sınavlarda Çıkan Konular</div>
  <ul>
    <li><b>CompTIA Security+:</b> Saldırı türleri ve ağ güvenliği temel prensipleri.</li>
    <li><b>CEH (Certified Ethical Hacker):</b> DoS/DDoS araçları, metodolojisi ve analizleri.</li>
    <li><b>OSCP:</b> Protokol seviyesinde analiz ve güvenlik duvarı atlatma senaryoları.</li>
  </ul>
</div>

</body>
</html>
"""
        return html_tpl.replace("{BG_COLOR}", bg_color).replace("{TEXT_COLOR}", text_color).replace("{CARD_BG}", card_bg).replace("{ACCENT_COLOR}", accent_color).replace("{BADGE_BG}", badge_bg).replace("{BADGE_TEXT}", badge_text).replace("{BORDER_COLOR}", border_color)

    # ── Simülatör Paneli ──────────────────────────────────────────

    def _dos_sim_olustur(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)

        # ── Başlık + Uyarı Bandı ──────────────────────────────────
        baslik = QLabel("🧪 Slowloris Simülatörü — Yalnızca Yerel Ağ")
        baslik.setStyleSheet(
            "font-size:16px; font-weight:bold; color:#ff6b35; padding:6px;"
        )
        layout.addWidget(baslik)

        uyari = QLabel(
            "⚠️  Yalnızca izin aldığın ya da sahibi olduğun sistemlere karşı kullan."
        )
        uyari.setWordWrap(True)
        uyari.setStyleSheet(
            "background:#2a1010; color:#ff8888; border:1px solid #ff4444; "
            "border-radius:5px; padding:8px 12px; font-size:12px;"
        )
        layout.addWidget(uyari)

        # ── Ayar Formu ────────────────────────────────────────────
        form_group = QGroupBox("⚙️ Simülasyon Parametreleri")
        form = QFormLayout()

        self.dos_hedef_input = QLineEdit()
        self.dos_hedef_input.setText("127.0.0.1")
        self.dos_hedef_input.setPlaceholderText("127.0.0.1 veya 192.168.x.x")

        self.dos_port_input = QSpinBox()
        self.dos_port_input.setRange(1, 65535)
        self.dos_port_input.setValue(80)

        self.dos_soket_input = QSpinBox()
        self.dos_soket_input.setRange(5, 200)
        self.dos_soket_input.setValue(50)
        self.dos_soket_input.setSuffix(" soket")

        self.dos_sure_input = QSpinBox()
        self.dos_sure_input.setRange(10, 300)
        self.dos_sure_input.setValue(60)
        self.dos_sure_input.setSuffix(" saniye")

        form.addRow("Hedef IP:", self.dos_hedef_input)
        form.addRow("Port:", self.dos_port_input)
        form.addRow("Maks Soket:", self.dos_soket_input)
        form.addRow("Süre Limiti:", self.dos_sure_input)
        form_group.setLayout(form)
        layout.addWidget(form_group)

        # ── İstatistik Göstergesi ─────────────────────────────────
        stat_group = QGroupBox("📊 Canlı İstatistik")
        stat_layout = QHBoxLayout()

        self.dos_stat_acik  = self._stat_karti("✅ Aktif Soket", "0", "#06d6a0")
        self.dos_stat_kapali= self._stat_karti("❌ Kapatılan",   "0", "#ff6b35")
        self.dos_stat_toplam= self._stat_karti("📡 Toplam Deneme","0","#4ecdc4")

        stat_layout.addWidget(self.dos_stat_acik)
        stat_layout.addWidget(self.dos_stat_kapali)
        stat_layout.addWidget(self.dos_stat_toplam)
        stat_group.setLayout(stat_layout)
        layout.addWidget(stat_group)

        # ── Butonlar ──────────────────────────────────────────────
        btn_layout = QHBoxLayout()

        self.dos_btn_baslat = QPushButton("▶  Simülasyonu Başlat")
        self.dos_btn_baslat.setFixedHeight(44)
        self.dos_btn_baslat.clicked.connect(self.dos_baslat)

        self.dos_btn_durdur = QPushButton("⛔  SİMÜLASYONU DURDUR")
        self.dos_btn_durdur.setFixedHeight(44)
        self.dos_btn_durdur.setEnabled(False)
        self.dos_btn_durdur.clicked.connect(self.dos_durdur)

        btn_temizle = QPushButton("🗑  Logu Temizle")
        btn_temizle.setFixedHeight(44)
        btn_temizle.clicked.connect(lambda: self.dos_log_ekrani.clear())

        btn_layout.addWidget(self.dos_btn_baslat, 3)
        btn_layout.addWidget(self.dos_btn_durdur, 3)
        btn_layout.addWidget(btn_temizle, 1)
        layout.addLayout(btn_layout)

        # ── Durum etiketi ─────────────────────────────────────────
        self.dos_durum_label = QLabel("Durum: Bekleniyor")
        layout.addWidget(self.dos_durum_label)

        # ── Log Ekranı ────────────────────────────────────────────
        log_group = QGroupBox("📋 Canlı Log Akışı")
        log_layout = QVBoxLayout()
        self.dos_log_ekrani = QTextBrowser()
        self.dos_log_ekrani.setMinimumHeight(200)
        log_layout.addWidget(self.dos_log_ekrani)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        return w

    def _stat_karti(self, etiket: str, deger: str, renk: str) -> QFrame:
        """Renkli istatistik kartı widget'ı oluşturur."""
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background:#111122; border:1px solid {renk}; "
            f"border-radius:6px; padding:6px; }}"
        )
        v = QVBoxLayout(frame)
        v.setSpacing(2)

        val_lbl = QLabel(deger)
        val_lbl.setObjectName(f"stat_val_{etiket}")
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val_lbl.setStyleSheet(
            f"color:{renk}; font-size:24px; font-weight:bold; border:none;"
        )

        key_lbl = QLabel(etiket)
        key_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        key_lbl.setStyleSheet("color:#888888; font-size:11px; border:none;")

        v.addWidget(val_lbl)
        v.addWidget(key_lbl)
        return frame

    def _stat_deger_guncelle(self, frame: QFrame, deger: str):
        """Stat kartındaki değeri günceller."""
        for child in frame.children():
            if isinstance(child, QLabel) and "stat_val_" in (child.objectName() or ""):
                child.setText(deger)
                return

    # ── DoS Kontrol Fonksiyonları ─────────────────────────────────

    def dos_baslat(self):
        """Simülasyonu doğrulama sonrası başlatır."""
        hedef = self.dos_hedef_input.text().strip()
        port  = self.dos_port_input.value()
        soket = self.dos_soket_input.value()
        sure  = self.dos_sure_input.value()

        # 1. Güvenlik Doğrulaması
        guvenli, mesaj = _hedef_guvenli_mi(hedef)
        if not guvenli:
            self.dos_log_ekrani.append(f"<span style='color:#ff4444'>{mesaj}</span>")
            QMessageBox.warning(self, "Güvenlik Engeli", mesaj)
            return

        self.dos_log_ekrani.append(f"<span style='color:#06d6a0'>{mesaj}</span>")

        # 2. Eski thread temizle
        if self.dos_thread and self.dos_thread.isRunning():
            self.dos_thread.durdur()
            self.dos_thread.wait(3000)

        # 3. Sayaçları sıfırla
        self._stat_deger_guncelle(self.dos_stat_acik,   "0")
        self._stat_deger_guncelle(self.dos_stat_kapali, "0")
        self._stat_deger_guncelle(self.dos_stat_toplam, "0")

        # 4. Thread oluştur ve başlat
        self.dos_thread = SlowlorisThread(hedef, port, soket, sure)
        self.dos_thread.log_sinyali.connect(self.dos_log_satir_ekle)
        self.dos_thread.istatistik_sinyali.connect(self.dos_istatistik_guncelle)
        self.dos_thread.bitti_sinyali.connect(self.dos_bitti)
        self.track_thread(self.dos_thread)
        self.dos_thread.start()

        # 5. UI Durumu
        self.dos_btn_baslat.setEnabled(False)
        self.dos_btn_durdur.setEnabled(True)
        self.dos_durum_label.setText(
            f"🟢 Durum: <b>Çalışıyor</b> → {hedef}:{port} | "
            f"Maks {soket} soket | {sure}s limit"
        )
        self.dos_durum_label.setStyleSheet(
            "color:#00ff00; font-size:12px; padding:2px;"
        )

    def dos_durdur(self):
        """Kill switch — tüm soketleri anında kapatır."""
        if self.dos_thread and self.dos_thread.isRunning():
            self.dos_thread.durdur()
            self.dos_log_ekrani.append(
                "<span style='color:#ff6b35'>⛔ Kullanıcı durdurdu — "
                "tüm soketler kapatılıyor...</span>"
            )
        self.dos_btn_durdur.setEnabled(False)
        self.dos_durum_label.setText("🔴 Durum: Durduruldu")
        self.dos_durum_label.setStyleSheet(
            "color:#ff6b35; font-size:12px; padding:2px;"
        )

    def dos_log_satir_ekle(self, satir: str):
        """Log satırını ekrana yazar, renk vurgular uygular."""
        if satir.startswith("[+]"):
            html = f"<span style='color:#06d6a0'>{satir}</span>"
        elif satir.startswith("[!]"):
            html = f"<span style='color:#ff6b35'>{satir}</span>"
        elif "═" in satir or "─" in satir or "ÖZET" in satir:
            html = f"<span style='color:#ffd166'><b>{satir}</b></span>"
        else:
            html = f"<span style='color:#cccccc'>{satir}</span>"
        self.dos_log_ekrani.append(html)

    def dos_istatistik_guncelle(self, acik: int, kapali: int, toplam: int):
        """Canlı istatistik kartlarını günceller."""
        self._stat_deger_guncelle(self.dos_stat_acik,    str(acik))
        self._stat_deger_guncelle(self.dos_stat_kapali,  str(kapali))
        self._stat_deger_guncelle(self.dos_stat_toplam,  str(toplam))

    def dos_bitti(self, mesaj: str):
        """Simülasyon tamamlandığında UI'yı günceller."""
        self.dos_btn_baslat.setEnabled(True)
        self.dos_btn_durdur.setEnabled(False)
        self.dos_durum_label.setText(f"✅ Durum: {mesaj}")
        self.dos_durum_label.setStyleSheet(
            "color:#4ecdc4; font-size:12px; padding:2px;"
        )

    # ═══════════════════════════════════════════════════════════════
    # TERMİNAL SEKMESİ
    # ═══════════════════════════════════════════════════════════════

    def terminal_sekmesi_olustur(self) -> QWidget:
        self._term_cwd = os.path.expanduser("~")   # başlangıç dizini
        self._term_gecmis = []                      # komut geçmişi
        self._term_gecmis_idx = -1
        self._term_thread = None

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        # ── Çıktı Ekranı ──────────────────────────────────────────
        from PyQt6.QtWidgets import QTextEdit
        self.term_ekran = QTextEdit()
        self.term_ekran.setReadOnly(True)
        self.term_ekran.setFont(QFont("Courier New", 11))
        self.term_ekran.setStyleSheet(
            "QTextEdit {"
            "  background:#0c0c0c; color:#cccccc;"
            "  border:1px solid #333; border-radius:4px;"
            "  padding:6px;"
            "}"
        )
        layout.addWidget(self.term_ekran, stretch=1)

        # ── Alt Bar (prompt + input + butonlar) ───────────────────
        alt = QHBoxLayout()

        self.term_prompt_lbl = QLabel(f"{self._term_cwd}>")
        self.term_prompt_lbl.setFont(QFont("Courier New", 10))
        self.term_prompt_lbl.setStyleSheet("color:#00ff00; padding-right:4px;")
        alt.addWidget(self.term_prompt_lbl)

        self.term_input = QLineEdit()
        self.term_input.setFont(QFont("Courier New", 11))
        self.term_input.setStyleSheet(
            "QLineEdit {"
            "  background:#1a1a1a; color:#00ff00;"
            "  border:1px solid #00aa00; border-radius:3px;"
            "  padding:4px 8px;"
            "}"
        )
        self.term_input.setPlaceholderText("Komut girin ve Enter'a basın...")
        self.term_input.returnPressed.connect(self.term_komut_calistir)
        self.term_input.installEventFilter(self)   # yukarı/aşağı ok
        alt.addWidget(self.term_input, stretch=1)

        btn_calistir = QPushButton("▶ Çalıştır")
        btn_calistir.setFixedWidth(90)
        btn_calistir.clicked.connect(self.term_komut_calistir)
        btn_calistir.setStyleSheet(
            "QPushButton { background:#004400; color:#00ff00;"
            "  border:1px solid #00aa00; border-radius:3px; padding:4px; }"
            "QPushButton:hover { background:#005500; }"
        )

        btn_iptal = QPushButton("⛔ İptal")
        btn_iptal.setFixedWidth(80)
        btn_iptal.clicked.connect(self.term_iptal)
        btn_iptal.setStyleSheet(
            "QPushButton { background:#440000; color:#ff5555;"
            "  border:1px solid #aa0000; border-radius:3px; padding:4px; }"
            "QPushButton:hover { background:#550000; }"
        )

        btn_temizle = QPushButton("🗑 Temizle")
        btn_temizle.setFixedWidth(90)
        btn_temizle.clicked.connect(self.term_temizle)
        btn_temizle.setStyleSheet(
            "QPushButton { background:#222; color:#aaa;"
            "  border:1px solid #555; border-radius:3px; padding:4px; }"
            "QPushButton:hover { background:#333; }"
        )

        alt.addWidget(btn_calistir)
        alt.addWidget(btn_iptal)
        alt.addWidget(btn_temizle)
        layout.addLayout(alt)

        # Karşılama mesajı
        self.term_ekran.append(
            '<span style="color:#00ff00">'
            '╔══════════════════════════════════════════════════╗<br>'
            '║&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Reiectus Securitas — Terminal&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;║<br>'
            '║&nbsp;&nbsp;cd &lt;dizin&gt; ile klasör değiştir | cls ile temizle&nbsp;&nbsp;║<br>'
            '╚══════════════════════════════════════════════════╝'
            '</span>'
        )
        return widget

    def eventFilter(self, obj, event):
        """Yukarı/aşağı ok ile komut geçmişi."""
        from PyQt6.QtCore import QEvent
        if obj is getattr(self, "term_input", None) and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if key == Qt.Key.Key_Up:
                if self._term_gecmis and self._term_gecmis_idx < len(self._term_gecmis) - 1:
                    self._term_gecmis_idx += 1
                    self.term_input.setText(self._term_gecmis[self._term_gecmis_idx])
                return True
            elif key == Qt.Key.Key_Down:
                if self._term_gecmis_idx > 0:
                    self._term_gecmis_idx -= 1
                    self.term_input.setText(self._term_gecmis[self._term_gecmis_idx])
                elif self._term_gecmis_idx == 0:
                    self._term_gecmis_idx = -1
                    self.term_input.clear()
                return True
        return super().eventFilter(obj, event)

    def term_komut_calistir(self):
        komut = self.term_input.text().strip()
        if not komut:
            return

        self._term_gecmis.insert(0, komut)
        self._term_gecmis = self._term_gecmis[:100]
        self._term_gecmis_idx = -1
        self.term_input.clear()

        self.term_ekran.append(
            f'<span style="color:#00ff00">{self._term_cwd.replace("<","&lt;")}&gt; {komut}</span>'
        )

        komut_lower = komut.strip().lower()

        # cls → temizle
        if komut_lower in ('cls', 'clear'):
            self.term_ekran.clear()
            return

        # cd → dizin değiştir
        if komut_lower.startswith('cd'):
            parts = komut.split(None, 1)
            hedef = parts[1] if len(parts) > 1 else os.path.expanduser('~')
            yeni = os.path.normpath(os.path.join(self._term_cwd, hedef))
            if os.path.isdir(yeni):
                self._term_cwd = yeni
                self.term_prompt_lbl.setText(f'{self._term_cwd}>')
            else:
                self.term_ekran.append(f'<span style="color:#ff5555">[HATA] Dizin bulunamadı: {yeni}</span>')    def _rev_rehber_html(self) -> str:
        # Temaya göre renkleri dinamik belirle
        if self.tema_modu == "Nebula":
            bg_color = "#0d0d1f"
            card_bg = "#121226"
            text_color = "#e1e1ff"
            accent_color = "#ff79c6"
            badge_bg = "#bd93f9"
            badge_text = "#0b0b16"
            border_color = "#bd93f9"
        elif self.tema_modu == "Hacker":
            bg_color = "#000000"
            card_bg = "#050905"
            text_color = "#39ff14"
            accent_color = "#39ff14"
            badge_bg = "#00aa00"
            badge_text = "#000000"
            border_color = "#39ff14"
        elif self.tema_modu == "Aydınlık":
            bg_color = "#f8fafc"
            card_bg = "#ffffff"
            text_color = "#0f172a"
            accent_color = "#2563eb"
            badge_bg = "#3b82f6"
            badge_text = "#ffffff"
            border_color = "#cbd5e1"
        elif self.tema_modu == "Tropik":
            bg_color = "#05201d"
            card_bg = "#0b332f"
            text_color = "#d2f5e3"
            accent_color = "#02c39a"
            badge_bg = "#ff9f1c"
            badge_text = "#05201d"
            border_color = "#00a896"
        elif self.tema_modu == "Mango":
            bg_color = "#fff8f0"
            card_bg = "#ffffff"
            text_color = "#2d3748"
            accent_color = "#ff6b81"
            badge_bg = "#badc58"
            badge_text = "#2d3748"
            border_color = "#ff6b81"
        else: # Karanlık (Midnight Slate)
            bg_color = "#0f172a"
            card_bg = "#1e293b"
            text_color = "#f1f5f9"
            accent_color = "#38bdf8"
            badge_bg = "#0284c7"
            badge_text = "#ffffff"
            border_color = "#334155"

        html_tpl = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{
    background: {bg_color};
    color: {text_color};
    font-family: 'Segoe UI', -apple-system, sans-serif;
    font-size: 13px;
    padding: 10px;
    margin: 0;
  }}
  .warn-banner {{
    background: rgba(255, 68, 68, 0.08);
    border-left: 4px solid #ff4444;
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 12px;
  }}
  .card {{
    background: {card_bg};
    border: 1px solid {border_color};
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 12px;
  }}
  .card h3 {{
    margin-top: 0;
    color: {accent_color};
  }}
  .accent {{ color: {accent_color}; font-weight: bold; }}
  .badge {{
    background: {badge_bg};
    color: {badge_text};
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
  }}
  code {{
    background: rgba(0,0,0,0.1);
    padding: 2px 4px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
  }}
  pre {{
    background: rgba(0,0,0,0.2);
    padding: 10px;
    border-radius: 5px;
    font-family: 'Courier New', monospace;
    font-size: 11.5px;
    overflow-x: auto;
  }}
  ul {{
    padding-left: 20px;
  }}
  li {{
    margin-bottom: 6px;
  }}
</style>
</head>
<body>

  <div class="warn-banner">
    <b>⚠️ EĞİTSEL UYARI:</b> Bu laboratuvar modülü, tersine mühendisliğin (Reverse Engineering) ve yazılım lisanslama bypass yöntemlerinin temel çalışma mantığını (Assembly Patching) görsel ve teorik olarak açıklamak amacıyla hazırlanmıştır. Ticari yazılımları cracklemek yasa dışıdır.
  </div>

  <div class="card">
    <h3>🔍 Sınıf 1: Tersine Mühendislik (Reverse Engineering) Nedir?</h3>
    <p>Derlenmiş (yani makine koduna / binary formatına dönüştürülmüş) bir yazılımın kaynak kodları olmadan, davranışlarını ve çalışma mantığını analiz etme sürecidir. Siber güvenlik uzmanları bu yöntemi hem zararlı yazılımları (malware) analiz etmek hem de uygulamalardaki güvenlik açıklarını bulmak için kullanırlar.</p>
  </div>

  <div class="card">
    <h3>🔇 Sınıf 2: Hata Mesajı Vermeden Kapananlar (Silent Crash Bypass)</h3>
    <p>Eğer bir uygulama şifreyi yanlış girdiğinizde hiçbir hata mesajı vermeden (Wrong Password vs. demeden) dümdüz kapanıyorsa, dize (String) aramak işe yaramaz. Çünkü gizli bir hata mesajı yoktur. x64dbg'de bunu çözmenin taktiği (API Breakpoint Taktikleri) şudur:</p>
    <ul>
      <li><span class="badge">ExitProcess Tuzağı</span> Bir program kapanırken mecburen Windows sistemine ait <code>ExitProcess</code> veya <code>TerminateProcess</code> isimli kodları çağırmak zorundadır. x64dbg'de en üstteki <b>Semboller (Symbols)</b> sekmesine geçip arama yerine <code>ExitProcess</code> yazarsınız. Çıkan sonuca sol tıklayıp <code>F2</code> tuşuna basarak breakpoint koyarsınız.</li>
      <li><span class="badge">Çağrı Yığını (Call Stack) Takibi</span> Programı <code>F9</code> ile çalıştırıp yanlış şifreyi girip onaylarsınız. Program kapanmaya çalıştığı an, kurduğunuz tuzağa (ExitProcess) takılıp duraklatılır (Paused). Hemen üstteki <b>Call Stack</b> sekmesine geçip programı kapatma emrinin hangi satırdan verildiğini görebilirsiniz.</li>
      <li><span class="badge">Geriye Dönüş ve Yama</span> Call Stack'te yazan programınızın adına (örn: crackme.exe) çift tıkladığınızda debugger sizi tam olarak programın hata verip kapandığı o bloğa ışınlar. Kodların biraz üstüne çıktığınızda şifre kontrolcüsünü (<code>TEST</code> veya <code>CMP</code>) ve ölüm atlamasını (<code>JZ</code> veya <code>JE</code>) görürsünüz. Onu <code>NOP</code> ile yamaladığınız an program bir daha kapanmaz, aksine içeri girer!</li>
    </ul>
  </div>

  <div class="card">
    <h3>💻 Sınıf 3: Assembly ve DRM Patching Mantığı</h3>
    <p>Yazılımlar C++, Delphi veya Assembly gibi dillerle yazıldığında, derleyici bunları bilgisayarın doğrudan çalıştırabileceği <span class="accent">x86/x64 Assembly makine kodlarına</span> dönüştürür. Yazılımın lisans kontrolü yapan satırı basit bir karşılaştırmadır:</p>
    <pre>
TEST EAX, EAX   ; Lisans doğrulandı mı? (Sonuç EAX'te tutulur)
JZ license_fail ; EAX sıfır ise (Eşitse) Hata etiketine atla!</pre>
    <p>Tersine mühendisler, x64dbg veya IDA Pro gibi hata ayıklayıcılar (debugger) ile bu adresi bulup, oradaki <code>JZ</code> (Jump if Zero) kodunu <code>NOP</code> (No Operation - Boş Geç) haline getirir veya koşulsuz atlayan <code>JMP</code> ile değiştirirler. Böylece yazılım, lisans anahtarı yanlış olsa bile hata satırını atlayarak doğrudan açılır! Buna <span class="accent">Binary Patching (İkili Yamalama)</span> denir.</p>
  </div>

  <div class="card">
    <h3>🎮 Sınıf 4: Oyun Crackleme (Steam Emulator & DLL Spoofing)</h3>
    <p>Birçok oyun Steam API (<code>steam_api.dll</code> veya <code>steam_api64.dll</code>) kütüphanesini kullanır. Bu DLL dosyaları oyun açılırken Steam sunucularına bağlanıp lisans kontrolü yapar.</p>
    <ul>
      <li><span class="badge">AppID Taklidi</span> Oyun klasörüne yerleştirilen basit bir <code>steam_appid.txt</code> dosyası, Steam sunucusuna oyunun kimliğini (AppID) bildirir.</li>
      <li><span class="badge">DLL Emülatörleri</span> Crack grupları, orijinal Steam DLL dosyasının yerine özel yazılmış sahte (emüle) bir DLL koyarak oyunun her lisans kontrol sorgusuna doğrudan <i>"Evet, bu kullanıcı oyuna sahip!"</i> cevabı vermesini sağlarlar.</li>
    </ul>
  </div>

  <div class="card">
    <h3>🛡️ Sınıf 5: Paketleyiciler ve Obfuscation (Packers & Protectors)</h3>
    <p>Birçok modern program ve oyun, tersine mühendisliği engellemek amacıyla paketlenir veya şifrelenir (UPX, Themida, VMProtect vb.).</p>
    <ul>
      <li><span class="badge">Manuel Unpacking</span> Hata ayıklayıcı yardımıyla programın bellekte tamamen açılmasını bekleyip OEP (Original Entry Point) noktasında dump dosyası alarak koruma aşılır.</li>
      <li><span class="badge">Kod Karıştırma</span> Kodun yapısını karıştırarak okunurluğu düşüren mekanizmaları çözmek için sembol analizörleri ve deobfuscator araçları kullanılır.</li>
    </ul>
  </div>

</body>
</html>
"""
        return html_tpl
    color: {badge_text};
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
  }}
  code {{
    background: rgba(0,0,0,0.1);
    padding: 2px 4px;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
  }}
  pre {{
    background: rgba(0,0,0,0.2);
    padding: 10px;
    border-radius: 5px;
    font-family: 'Courier New', monospace;
    font-size: 11.5px;
    overflow-x: auto;
  }}
</style>
</head>
<body>

  <div class="warn-banner">
    <b>⚠️ EĞİTSEL UYARI:</b> Bu laboratuvar modülü, tersine mühendisliğin (Reverse Engineering) ve yazılım lisanslama bypass yöntemlerinin temel çalışma mantığını (Assembly Patching) görsel ve teorik olarak açıklamak amacıyla hazırlanmıştır. Ticari yazılımları cracklemek yasa dışıdır.
  </div>

  <div class="card">
    <h3>🔍 Tersine Mühendislik (Reverse Engineering) Nedir?</h3>
    <p>Derlenmiş (yani makine koduna / binary formatına dönüştürülmüş) bir yazılımın kaynak kodları olmadan, davranışlarını ve çalışma mantığını analiz etme sürecidir. Siber güvenlik uzmanları bu yöntemi hem zararlı yazılımları (malware) analiz etmek hem de uygulamalardaki güvenlik açıklarını bulmak için kullanırlar.</p>
  </div>

  <div class="card">
    <h3>💻 Assembly ve DRM Patching Mantığı</h3>
    <p>Yazılımlar C++, Delphi veya Assembly gibi dillerle yazıldığında, derleyici bunları bilgisayarın doğrudan çalıştırabileceği <span class="accent">x86/x64 Assembly makine kodlarına</span> dönüştürür. Yazılımın lisans kontrolü yapan satırı basit bir karşılaştırmadır:</p>
    <pre>
TEST EAX, EAX   ; Lisans doğrulandı mı? (Sonuç EAX'te tutulur)
JZ license_fail ; EAX sıfır ise (Eşitse) Hata etiketine atla!</pre>
    <p>Tersine mühendisler, x64dbg veya IDA Pro gibi hata ayıklayıcılar (debugger) ile bu adresi bulup, oradaki <code>JZ</code> (Jump if Zero) kodunu <code>NOP</code> (No Operation - Boş Geç) haline getirir veya koşulsuz atlayan <code>JMP</code> ile değiştirirler. Böylece yazılım, lisans anahtarı yanlış olsa bile hata satırını atlayarak doğrudan açılır! Buna <span class="accent">Binary Patching (İkili Yamalama)</span> denir.</p>
  </div>

  <div class="card">
    <h3>🎮 Steam Emulator & DLL Spoofing Nedir?</h3>
    <p>Birçok oyun Steam API (<code>steam_api.dll</code> veya <code>steam_api64.dll</code>) kütüphanesini kullanır. Bu DLL dosyaları oyun açılırken Steam sunucularına bağlanıp lisans kontrolü yapar.</p>
    <ul>
      <li><span class="badge">AppID Taklidi</span> Oyun klasörüne yerleştirilen basit bir <code>steam_appid.txt</code> dosyası, Steam sunucusuna oyunun kimliğini (AppID) bildirir.</li>
      <li><span class="badge">DLL Emülatörleri</span> Crack grupları, orijinal Steam DLL dosyasının yerine özel yazılmış sahte (emüle) bir DLL koyarak oyunun her lisans kontrol sorgusuna doğrudan <i>"Evet, bu kullanıcı oyuna sahip!"</i> cevabı vermesini sağlarlar.</li>
    </ul>
  </div>

</body>
</html>
"""
        return html_tpl

    # ── Simülatör (CrackMe Lab) ───────────────────────────────────

    def _rev_sim_olustur(self) -> QWidget:
        w = QWidget()
        layout = QHBoxLayout(w)

        # Sol taraf: Debugger Disassembly Görünümü ve Patch Butonları
        sol = QVBoxLayout()
        sol.addWidget(QLabel("<b>🖥️ Debugger Disassembly Görünümü (Makine Kodları)</b>"))
        
        self.rev_table = QTableWidget()
        self.rev_table.setColumnCount(3)
        self.rev_table.setHorizontalHeaderLabels(["Adres", "Makine Kodu (Assembly)", "Yorum"])
        self.rev_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.rev_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.rev_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        sol.addWidget(self.rev_table)

        # Patch Butonları
        btn_layout = QHBoxLayout()
        self.rev_btn_nop = QPushButton("🛠️ Satırı NOP ile Yama (Patch)")
        self.rev_btn_nop.clicked.connect(self.rev_patch_nop)
        self.rev_btn_jmp = QPushButton("⚡ Satırı JMP Yap")
        self.rev_btn_jmp.clicked.connect(self.rev_patch_jmp)
        self.rev_btn_reset = QPushButton("🔄 Simülasyonu Sıfırla")
        self.rev_btn_reset.clicked.connect(self.rev_reset_sim)
        
        btn_layout.addWidget(self.rev_btn_nop)
        btn_layout.addWidget(self.rev_btn_jmp)
        btn_layout.addWidget(self.rev_btn_reset)
        sol.addLayout(btn_layout)

        # Sağ taraf: Kullanıcı Arayüzü, Seri Anahtarı Testi ve Çıktı Ekranı
        sag = QVBoxLayout()
        
        # Lisans Kontrol Kartı
        serial_group = QGroupBox("🎮 Korumalı Oyun Arayüzü")
        serial_layout = QVBoxLayout()
        serial_layout.addWidget(QLabel("Lütfen Lisans Anahtarını (Serial Key) Girin:"))
        
        self.rev_serial_input = QLineEdit()
        self.rev_serial_input.setPlaceholderText("Örn: XXXX-XXXX-XXXX-XXXX")
        serial_layout.addWidget(self.rev_serial_input)
        
        self.rev_btn_run = QPushButton("🚀 Oyunu Çalıştır (Run Game)")
        self.rev_btn_run.clicked.connect(self.rev_oyunu_calistir)
        serial_layout.addWidget(self.rev_btn_run)
        serial_group.setLayout(serial_layout)
        sag.addWidget(serial_group)

        # Çıktı / Log Ekranı (Siyah Konsol)
        sag.addWidget(QLabel("<b>💻 Debugger / Konsol Log Ekranı</b>"))
        self.rev_log_ekrani = QTextBrowser()
        self.rev_log_ekrani.setStyleSheet("background: #090e0c; color: #39ff14; font-family: 'Courier New', monospace; font-size: 12px; border: 1px solid #ff6b81;")
        sag.addWidget(self.rev_log_ekrani)

        layout.addLayout(sol, 3)
        layout.addLayout(sag, 2)

        # Simülasyon Verilerini Doldur
        self.rev_reset_sim()
        return w

    def rev_reset_sim(self):
        """Simülasyon durumunu orijinal kodlara sıfırlar."""
        self.rev_instructions = [
            {"addr": "0x004015A0", "code": "MOV EAX, [ESP+0x04]", "comment": "Kullanıcının girdiği seri anahtarını yükle", "orig_code": "MOV EAX, [ESP+0x04]", "orig_comment": "Kullanıcının girdiği seri anahtarını yükle"},
            {"addr": "0x004015A4", "code": "CALL check_license", "comment": "Lisans doğrulama fonksiyonunu çağır", "orig_code": "CALL check_license", "orig_comment": "Lisans doğrulama fonksiyonunu çağır"},
            {"addr": "0x004015A9", "code": "TEST EAX, EAX", "comment": "Doğrulama sonucunu test et (EAX == 0 ise geçersiz)", "orig_code": "TEST EAX, EAX", "orig_comment": "Doğrulama sonucunu test et (EAX == 0 ise geçersiz)"},
            {"addr": "0x004015AB", "code": "JZ 0x004015B3", "comment": "EAX 0 ise (Geçersiz Key) license_failed etiketine atla", "orig_code": "JZ 0x004015B3", "orig_comment": "EAX 0 ise (Geçersiz Key) license_failed etiketine atla"},
            {"addr": "0x004015AD", "code": "MOV EDX, 1", "comment": "Lisans BAŞARILI bayrağını ayarla (EDX=1)", "orig_code": "MOV EDX, 1", "orig_comment": "Lisans BAŞARILI bayrağını ayarla (EDX=1)"},
            {"addr": "0x004015B2", "code": "RET", "comment": "Fonksiyondan dön (Başarılı)", "orig_code": "RET", "orig_comment": "Fonksiyondan dön (Başarılı)"},
            {"addr": "0x004015B3", "code": "license_failed:", "comment": "Lisans Başarısız Etiketi", "orig_code": "license_failed:", "orig_comment": "Lisans Başarısız Etiketi"},
            {"addr": "0x004015B4", "code": "MOV EDX, 0", "comment": "Lisans BAŞARISIZ bayrağını ayarla (EDX=0)", "orig_code": "MOV EDX, 0", "orig_comment": "Lisans BAŞARISIZ bayrağını ayarla (EDX=0)"},
            {"addr": "0x004015B9", "code": "RET", "comment": "Fonksiyondan dön (Başarısız)", "orig_code": "RET", "orig_comment": "Fonksiyondan dön (Başarısız)"}
        ]
        self.rev_table.setRowCount(len(self.rev_instructions))
        for r, inst in enumerate(self.rev_instructions):
            self.rev_table.setItem(r, 0, QTableWidgetItem(inst["addr"]))
            self.rev_table.setItem(r, 1, QTableWidgetItem(inst["code"]))
            self.rev_table.setItem(r, 2, QTableWidgetItem(inst["comment"]))
        
        self.rev_log_ekrani.setPlainText("[SYSTEM] Debugger başlatıldı.\n[SYSTEM] x86 Disassembly başarıyla yüklendi.\n[DRM] Oyun çalıştırılmaya hazır. Lisans bekleniyor...")

    def rev_patch_nop(self):
        """Seçilen assembly satırını NOP (No Operation) yapar."""
        row = self.rev_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Yarıda Kaldı", "Lütfen yamalamak istediğiniz Assembly satırını seçin!")
            return
        
        inst = self.rev_instructions[row]
        inst["code"] = "NOP"
        inst["comment"] = "[YAMALANDI] İşlem yapmadan geç (No Operation - Bypass)"
        
        self.rev_table.setItem(row, 1, QTableWidgetItem(inst["code"]))
        self.rev_table.setItem(row, 2, QTableWidgetItem(inst["comment"]))
        self.rev_log_ekrani.append(f"[DEBUGGER] {inst['addr']} adresi NOP ile yamanarak etkisizleştirildi!")

    def rev_patch_jmp(self):
        """Seçilen atlama satırını (örn JZ) koşulsuz atlamaya (JMP) çevirir."""
        row = self.rev_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Yarıda Kaldı", "Lütfen yamalamak istediğiniz Assembly satırını seçin!")
            return
        
        inst = self.rev_instructions[row]
        if "JZ" in inst["code"] or "JNZ" in inst["code"]:
            inst["code"] = "JMP 0x004015AD"
            inst["comment"] = "[YAMALANDI] Koşulu umursamadan doğrudan Başarılı Kod alanına atla!"
            self.rev_table.setItem(row, 1, QTableWidgetItem(inst["code"]))
            self.rev_table.setItem(row, 2, QTableWidgetItem(inst["comment"]))
            self.rev_log_ekrani.append(f"[DEBUGGER] {inst['addr']} adresindeki koşullu zıplama JMP (koşulsuz) olarak yamanarak yönlendirildi!")
        else:
            QMessageBox.information(self, "Bilgi", "JMP yaması sadece JZ gibi dallanma/koşullu zıplama satırlarında anlamlıdır.")

    def rev_oyunu_calistir(self):
        """Simüle edilmiş oyunu çalıştırır ve yamaları kontrol eder."""
        serial = self.rev_serial_input.text().strip()
        self.rev_log_ekrani.append("\n[GAME] Oyun başlatılıyor (Reiectus_Game.exe)...")
        self.rev_log_ekrani.append("[DRM] Lisans anahtarı kontrol mekanizması tetiklendi.")
        self.rev_log_ekrani.append(f"[DRM] Girilen Anahtar: '{serial}'")

        # Gerçek geçerli key (Keygen çözümü simülasyonu için)
        dogru_mu = (serial == "REIECTUS-K4Y-2026")

        # Adım adım x86 akışını simüle et
        self.rev_log_ekrani.append("[x86 CPU] 0x004015A0: MOV EAX, seri_anahtari yüklendi.")
        self.rev_log_ekrani.append("[x86 CPU] 0x004015A4: CALL check_license tetiklendi.")
        
        if dogru_mu:
            self.rev_log_ekrani.append("[DRM] -> Lisans doğrulama algoritması GEÇERLİ anahtarı onayladı! (EAX = 1)")
            eax = 1
        else:
            self.rev_log_ekrani.append("[DRM] -> Lisans doğrulama algoritması GEÇERSİZ anahtar hatası döndürdü! (EAX = 0)")
            eax = 0

        self.rev_log_ekrani.append(f"[x86 CPU] 0x004015A9: TEST EAX, EAX (EAX değeri test ediliyor: {eax})")
        
        # JZ satırının güncel durumunu kontrol et
        jz_instruction = self.rev_instructions[3]  # JZ satırı index 3'te
        
        if jz_instruction["code"] == "NOP":
            self.rev_log_ekrani.append("[x86 CPU] 0x004015AB: NOP algılandı! Kontrol atlandı, kod doğrudan akmaya devam ediyor.")
            self.rev_log_ekrani.append("[x86 CPU] 0x004015AD: MOV EDX, 1 (Lisans BAŞARILI durum bayrağı yazıldı!)")
            self.rev_log_ekrani.append("[x86 CPU] 0x004015B2: RET çalıştırıldı.")
            self.rev_log_ekrani.append("<b>[SUCCESS] OYUN KORUMASI BAŞARIYLA CRACKLENDİ! OYUN AÇILDI! 🎉</b>")
            QMessageBox.information(self, "Tebrikler!", "Harika! Lisans kontrol zıplamasını (JZ) NOP yayıyla etkisiz hale getirdin ve korumayı başarıyla aştın! 🔓🔥")
        elif jz_instruction["code"] == "JMP 0x004015AD":
            self.rev_log_ekrani.append("[x86 CPU] 0x004015AB: JMP 0x004015AD (Koşulsuz doğrudan başarılı alana zıplama yapıldı!)")
            self.rev_log_ekrani.append("[x86 CPU] 0x004015AD: MOV EDX, 1 (Lisans BAŞARILI durum bayrağı yazıldı!)")
            self.rev_log_ekrani.append("[x86 CPU] 0x004015B2: RET çalıştırıldı.")
            self.rev_log_ekrani.append("<b>[SUCCESS] OYUN KORUMASI BAŞARIYLA CRACKLENDİ! OYUN AÇILDI! 🎉</b>")
            QMessageBox.information(self, "Tebrikler!", "Harika! JZ zıplamasını doğrudan JMP 0x004015AD yaparak başarılı adresine yönlendirdin ve korumayı alt ettin! 🔓💎")
        else:
            # Yamalanmamış orijinal akış
            if eax == 0:
                self.rev_log_ekrani.append("[x86 CPU] 0x004015AB: JZ 0x004015B3 tetiklendi! (EAX sıfır olduğu için hata adresine atlanıyor...)")
                self.rev_log_ekrani.append("[x86 CPU] 0x004015B4: MOV EDX, 0 (Lisans BAŞARISIZ bayrağı yazıldı!)")
                self.rev_log_ekrani.append("[x86 CPU] 0x004015B9: RET (Fonksiyon sonlandırıldı)")
                self.rev_log_ekrani.append("<span style='color:#ff0000'>[ERROR] HATA: LİSANS ANAHTARI GEÇERSİZ! OYUN KİLİTLENDİ.</span>")
                QMessageBox.critical(self, "Hata", "Lisans doğrulaması başarısız oldu! Lütfen x86 kodlarını inceleyerek korumayı atlatmayı dene.")
            else:
                self.rev_log_ekrani.append("[x86 CPU] 0x004015AB: JZ atlanmadı (EAX sıfır değil). Akış devam ediyor...")
                self.rev_log_ekrani.append("[x86 CPU] 0x004015AD: MOV EDX, 1 (Lisans BAŞARILI bayrağı yazıldı)")
                self.rev_log_ekrani.append("[x86 CPU] 0x004015B2: RET çalıştırıldı.")
                self.rev_log_ekrani.append("<b>[SUCCESS] GEÇERLİ KEY: OYUN BAŞARIYLA BAŞLATILDI!</b>")
                QMessageBox.information(self, "Başarılı", "Doğru lisans anahtarını girerek oyunu başarıyla başlattın! (Şimdi bir de kodları yamalayarak açmayı dene!)")

    def _pe_analizor_olustur(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(2, 2, 2, 2)
        
        # 1. Menü ve Toolbar (x64dbg stili)
        toolbar_layout = QHBoxLayout()
        btn_open = QPushButton("📂 Aç (F3)")
        btn_open.clicked.connect(self.pe_dosyasi_ac)
        
        self.btn_pe_run = QPushButton("▶️ Çalıştır (F9)")
        self.btn_pe_pause = QPushButton("⏸️ Duraklat (F12)")
        
        self.btn_pe_f8 = QPushButton("⬇️ Adım Geç (F8)")
        self.btn_pe_f8.clicked.connect(self.pe_step_over)
        self.btn_pe_f8.setEnabled(False)
        
        self.btn_pe_altf9 = QPushButton("⏩ Kullanıcı Koduna Git (Alt+F9)")
        self.btn_pe_altf9.clicked.connect(self.pe_run_to_user)
        self.btn_pe_altf9.setEnabled(False)
        
        self.btn_pe_strings = QPushButton("🔍 Referansları Ara (Strings)")
        self.btn_pe_strings.clicked.connect(self.pe_search_strings)
        self.btn_pe_strings.setEnabled(False)
        
        toolbar_layout.addWidget(btn_open)
        toolbar_layout.addWidget(self.btn_pe_run)
        toolbar_layout.addWidget(self.btn_pe_pause)
        toolbar_layout.addWidget(self.btn_pe_f8)
        toolbar_layout.addWidget(self.btn_pe_altf9)
        toolbar_layout.addWidget(self.btn_pe_strings)
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)

        # 2. Üst Sekmeler
        tabs = QTabWidget()
        tab_cpu = QWidget()
        tab_log = QWidget()
        tabs.addTab(tab_cpu, "CPU")
        tabs.addTab(tab_log, "Log")
        tabs.addTab(QWidget(), "Breakpoints")
        tabs.addTab(QWidget(), "Memory Map")
        tabs.addTab(QWidget(), "Call Stack")
        
        # --- CPU TAB DİZAYNI (4'LÜ QUADRANT) ---
        cpu_layout = QVBoxLayout(tab_cpu)
        cpu_layout.setContentsMargins(0, 0, 0, 0)
        
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Üst Splitter: Disassembly ve Registers
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Disassembly View
        disasm_widget = QWidget()
        disasm_layout = QVBoxLayout(disasm_widget)
        disasm_layout.setContentsMargins(0,0,0,0)
        self.pe_disasm_table = QTableWidget()
        self.pe_disasm_table.setColumnCount(4)
        self.pe_disasm_table.setHorizontalHeaderLabels(["Address", "Hex", "Disassembly", "Comment"])
        self.pe_disasm_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pe_disasm_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pe_disasm_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.pe_disasm_table.setFont(QFont("Courier New", 10))
        
        bg_col = "#ffffff" if self.tema_modu not in ["Hacker", "Nebula", "Tropik"] else ("#090e0c" if self.tema_modu=="Hacker" else "#121226")
        fg_col = "#000000" if self.tema_modu not in ["Hacker", "Nebula", "Tropik"] else ("#39ff14" if self.tema_modu=="Hacker" else "#e1e1ff")
        self.pe_disasm_table.setStyleSheet(f"QTableWidget {{ background-color: {bg_col}; color: {fg_col}; gridline-color: #555555; selection-background-color: #555555; }}")
        disasm_layout.addWidget(self.pe_disasm_table)
        
        # Registers View
        regs_widget = QWidget()
        regs_layout = QVBoxLayout(regs_widget)
        regs_layout.setContentsMargins(0,0,0,0)
        regs_layout.addWidget(QLabel("<b>Registers (FPU)</b>"))
        
        reg_form = QFormLayout()
        self.lbl_reg_rax = QLabel("0000000000000000")
        self.lbl_reg_rbx = QLabel("0000000000000000")
        self.lbl_reg_rcx = QLabel("0000000000000000")
        self.lbl_reg_rdx = QLabel("0000000000000000")
        self.lbl_reg_rip = QLabel("0000000000000000")
        for lbl in [self.lbl_reg_rax, self.lbl_reg_rbx, self.lbl_reg_rcx, self.lbl_reg_rdx, self.lbl_reg_rip]:
            lbl.setFont(QFont("Courier New", 10))
            lbl.setStyleSheet(f"color: {fg_col};")
            
        reg_form.addRow("RAX", self.lbl_reg_rax)
        reg_form.addRow("RBX", self.lbl_reg_rbx)
        reg_form.addRow("RCX", self.lbl_reg_rcx)
        reg_form.addRow("RDX", self.lbl_reg_rdx)
        reg_form.addRow("RIP", self.lbl_reg_rip)
        
        reg_group = QGroupBox()
        reg_group.setLayout(reg_form)
        regs_layout.addWidget(reg_group)
        regs_layout.addStretch()
        
        top_splitter.addWidget(disasm_widget)
        top_splitter.addWidget(regs_widget)
        top_splitter.setSizes([700, 300])
        
        # Alt Splitter: Hex Dump ve Stack
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Hex Dump View
        dump_widget = QWidget()
        dump_layout = QVBoxLayout(dump_widget)
        dump_layout.setContentsMargins(0,0,0,0)
        dump_layout.addWidget(QLabel("<b>Dump 1</b>"))
        self.pe_hex_dump = QTextBrowser()
        self.pe_hex_dump.setFont(QFont("Courier New", 10))
        self.pe_hex_dump.setStyleSheet(f"background-color: {bg_col}; color: {fg_col};")
        dump_layout.addWidget(self.pe_hex_dump)
        
        # Stack View
        stack_widget = QWidget()
        stack_layout = QVBoxLayout(stack_widget)
        stack_layout.setContentsMargins(0,0,0,0)
        stack_layout.addWidget(QLabel("<b>Stack</b>"))
        self.pe_stack_view = QTextBrowser()
        self.pe_stack_view.setFont(QFont("Courier New", 10))
        self.pe_stack_view.setStyleSheet(f"background-color: {bg_col}; color: {fg_col};")
        stack_layout.addWidget(self.pe_stack_view)
        
        bottom_splitter.addWidget(dump_widget)
        bottom_splitter.addWidget(stack_widget)
        bottom_splitter.setSizes([700, 300])
        
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([600, 200])
        
        cpu_layout.addWidget(main_splitter)
        
        # --- LOG TAB DİZAYNI ---
        log_tab_layout = QVBoxLayout(tab_log)
        self.pe_log_ekrani = QTextBrowser()
        self.pe_log_ekrani.setStyleSheet("background: #090e0c; color: #39ff14; font-family: 'Courier New', monospace; font-size: 11px;")
        log_tab_layout.addWidget(self.pe_log_ekrani)
        
        layout.addWidget(tabs)
        
        # Yamalama Paneli
        patch_layout = QHBoxLayout()
        patch_layout.addWidget(QLabel("<i>Assembly Kodlarını Yamalamak İçin:</i>"))
        patch_layout.addStretch()
        self.btn_pe_nop = QPushButton("Satırı NOP Yap")
        self.btn_pe_nop.clicked.connect(self.pe_patch_nop)
        self.btn_pe_custom = QPushButton("Özel Opcode Yaz (Patch)")
        self.btn_pe_custom.clicked.connect(self.pe_patch_custom)
        patch_layout.addWidget(self.btn_pe_nop)
        patch_layout.addWidget(self.btn_pe_custom)
        layout.addLayout(patch_layout)

        # Durum Çubuğu
        self.pe_status_bar = QLabel("Durum: Duraklatıldı | Modül: ntdll.dll")
        self.pe_status_bar.setStyleSheet("background-color: #007acc; color: white; padding: 3px; font-weight: bold;")
        layout.addWidget(self.pe_status_bar)

        # Register Paneli (Simülatör için)
        reg_box = QGroupBox("⚙️ Register (Yazmaç) Görünümü")
        reg_layout = QFormLayout()
        self.lbl_reg_rax = QLabel("0x0000000000000000")
        self.lbl_reg_rbx = QLabel("0x0000000000000000")
        self.lbl_reg_rcx = QLabel("0x0000000000000000")
        self.lbl_reg_rdx = QLabel("0x0000000000000000")
        self.lbl_reg_rip = QLabel("0x0000000000000000")
        reg_layout.addRow("RAX/EAX:", self.lbl_reg_rax)
        reg_layout.addRow("RBX/EBX:", self.lbl_reg_rbx)
        reg_layout.addRow("RCX/ECX:", self.lbl_reg_rcx)
        reg_layout.addRow("RDX/EDX:", self.lbl_reg_rdx)
        reg_layout.addRow("RIP/EIP:", self.lbl_reg_rip)
        reg_box.setLayout(reg_layout)
        sag.addWidget(reg_box)

        # Log & Import Analiz Paneli
        sag.addWidget(QLabel("<b>📋 Debugger Analiz Logları</b>"))
        self.pe_log_ekrani = QTextBrowser()
        self.pe_log_ekrani.setStyleSheet("background: #090e0c; color: #39ff14; font-family: 'Courier New', monospace; font-size: 11px;")
        sag.addWidget(self.pe_log_ekrani, 2)

        layout.addLayout(sol, 3)
        layout.addLayout(sag, 2)

        # Kısayollar
        self.shortcut_f8 = QShortcut(QKeySequence("F8"), w)
        self.shortcut_f8.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.shortcut_f8.activated.connect(self.pe_step_over)
        
        self.shortcut_altf9 = QShortcut(QKeySequence("Alt+F9"), w)
        self.shortcut_altf9.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.shortcut_altf9.activated.connect(self.pe_run_to_user)

        # Sıfırlama durum bilgisi
        self.aktif_pe_yolu = None
        self.aktif_pe_data = None
        self.aktif_pe_instructions = []
        self.pe_state = 0
        self.pe_current_row = -1
        return w

    def pe_dosyasi_ac(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Analiz İçin PE Dosyası Seç (.exe, .dll)", "", "Executable Files (*.exe *.dll)")
        if not file_path:
            return
        
        self.aktif_pe_yolu = file_path
        self.lbl_secili_pe.setText(f"Analiz Edilen Dosya: {os.path.basename(file_path)}")
        self.pe_analiz_et(file_path)

    def pe_analiz_et(self, file_path):
        try:
            self.pe_log_ekrani.clear()
            self.pe_log_ekrani.append(f"[INFO] Dosya okunuyor: {file_path}")
            
            # pefile ile başlıkları yükle
            pe = pefile.PE(file_path)
            
            # Mimari Tespiti
            is_64bit = False
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                mimari = "x64 (64-Bit)"
                is_64bit = True
            elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                mimari = "x86 (32-Bit)"
            else:
                mimari = "Bilinmeyen / Diğer"

            self.lbl_pe_mimari.setText(mimari)
            
            # Entry Point (Giriş Noktası)
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            ep_va = image_base + entry_point
            self.lbl_pe_entry.setText(f"0x{ep_va:08X} (RVA: 0x{entry_point:08X})")
            
            # Kesitler (Sections)
            section_names = [sec.Name.decode('utf-8', errors='ignore').strip('\x00') for sec in pe.sections]
            self.lbl_pe_sections.setText(", ".join(section_names))
            
            # Register simülasyonunu güncelle
            self.lbl_reg_rip.setText(f"0x{ep_va:X}")
            self.lbl_reg_rax.setText("0x0000000000000000")
            self.lbl_reg_rbx.setText("0x0000000000000000")
            self.lbl_reg_rcx.setText("0x00000000")
            self.lbl_reg_rdx.setText("0x00000000")

            self.pe_log_ekrani.append(f"[INFO] Dosya Yüklendi. Image Base: 0x{image_base:X}")
            self.pe_log_ekrani.append(f"[INFO] Giriş Noktası Adresi (EP VA): 0x{ep_va:X}")
            self.pe_log_ekrani.append(f"[INFO] Toplam Bölüm (Section) Sayısı: {len(pe.sections)}")
            
            # İthal Edilen Fonksiyonlar (Imports) Analizi
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.pe_log_ekrani.append("\n[+] Önemli Kütüphane / API Çağrıları:")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    self.pe_log_ekrani.append(f" -> Kütüphane: {dll_name}")
                    for imp in entry.imports:
                        imp_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal: {imp.ordinal}"
                        # Şüpheli olabilecek API çağrılarını loga düşür
                        if any(x in imp_name.lower() for x in ["virtualalloc", "writeprocessmemory", "regcreatekey", "httpopen", "socket", "createprocess", "loadlibrary"]):
                            self.pe_log_ekrani.append(f"    ⚠️ HASSAS API: {imp_name}")
                        else:
                            self.pe_log_ekrani.append(f"    - {imp_name}")
            
            # Disassemble et (Capstone motoru ile)
            self.disassemble_ve_doldur(pe, file_path, is_64bit)
            
            # Eğitim simülasyonu ntdll.dll durumu
            self.pe_state = 1
            self.pe_status_bar.setText(f"Durum: DURAKLATILDI (Paused) | Modül: ntdll.dll")
            self.pe_status_bar.setStyleSheet("background-color: #cc2222; color: white; padding: 3px; font-weight: bold;")
            
            self.btn_pe_altf9.setEnabled(True)
            self.btn_pe_f8.setEnabled(False)
            self.btn_pe_strings.setEnabled(False)
            
            self.pe_disasm_table.setRowCount(0)
            self.pe_log_ekrani.append("\n[DEBUGGER] Dosya hata ayıklayıcıya aktarıldı.")
            self.pe_log_ekrani.append("[DEBUGGER] Durum: DURAKLATILDI (Paused) -> ntdll.dll giriş noktasındasınız (Simülasyon).")
            
        except Exception as e:
            self.pe_log_ekrani.append(f"<span style='color:red;'>[HATA] PE Analizinde hata oluştu: {str(e)}</span>")
            QMessageBox.critical(self, "Hata", f"PE Analiz hatası: {str(e)}")

    def disassemble_ve_doldur(self, pe, file_path, is_64bit):
        try:
            # Entry point'in bulunduğu kesiti arayalım
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            code_section = None
            for section in pe.sections:
                # EP bu section içindeyse kodu disassemble et
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    code_section = section
                    break

            if not code_section:
                # İlk kesiti varsayılan olarak seç
                code_section = pe.sections[0]

            # Dosyadan binary içeriği oku
            with open(file_path, "rb") as f:
                self.aktif_pe_data = bytearray(f.read())
            
            # Kod kesitinin offset'ini ve ham verisini çıkar
            offset = code_section.PointerToRawData
            size = code_section.SizeOfRawData
            code_bytes = self.aktif_pe_data[offset : offset + size]
            
            image_base = pe.OPTIONAL_HEADER.ImageBase
            section_va = image_base + code_section.VirtualAddress

            # Capstone motorunu mimariye göre ayarla
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            
            # Yalnızca ilk 100 talimatı göster (Arayüz performansı ve eğitici netlik için)
            self.aktif_pe_instructions = []
            count = 0
            for insn in md.disasm(code_bytes, section_va):
                if count > 120:
                    break
                self.aktif_pe_instructions.append({
                    "va": insn.address,
                    "offset": offset + (insn.address - section_va),
                    "size": insn.size,
                    "bytes": " ".join(f"{b:02X}" for b in insn.bytes),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str
                })
                count += 1

            # Sadece talimat listesini hazırla, tabloya Kullanıcı Koduna Sıçrandığında eklenecek
            self.pe_log_ekrani.append(f"[SUCCESS] {len(self.aktif_pe_instructions)} adet x86/x64 talimatı hafızaya alındı (Henüz görüntülenmiyor).")
            
        except Exception as e:
            self.pe_log_ekrani.append(f"[HATA] Disassembly motoru başarısız: {str(e)}")

    def pe_run_to_user(self):
        if self.pe_state != 1: return
        self.pe_state = 2
        self.btn_pe_altf9.setEnabled(False)
        self.btn_pe_f8.setEnabled(True)
        self.btn_pe_strings.setEnabled(True)
        
        self.pe_status_bar.setText(f"Durum: DURAKLATILDI (Paused) | Modül: {os.path.basename(self.aktif_pe_yolu)}")
        self.pe_status_bar.setStyleSheet("background-color: #cc2222; color: white; padding: 3px; font-weight: bold;")
        self.pe_log_ekrani.append("\n[DEBUGGER] Kullanıcı kodu modülüne sıçrandı (Entry Point).")
        
        # Tabloyu şimdi doldur
        self.pe_disasm_table.setRowCount(len(self.aktif_pe_instructions))
        for row, inst in enumerate(self.aktif_pe_instructions):
            self.pe_disasm_table.setItem(row, 0, QTableWidgetItem(f"0x{inst['va']:08X}"))
            self.pe_disasm_table.setItem(row, 1, QTableWidgetItem(inst["bytes"]))
            self.pe_disasm_table.setItem(row, 2, QTableWidgetItem(f"{inst['mnemonic']} {inst['op_str']}"))
            
            aciklama = "-"
            mn = inst['mnemonic'].lower()
            if mn == "jmp": aciklama = "Koşulsuz Atlama"
            elif mn in ["jz", "je"]: aciklama = "Eşitse Atlama (Lisans Kontrollerinde Kritik)"
            elif mn in ["jnz", "jne"]: aciklama = "Eşit Değilse Atlama (Lisans Kontrollerinde Kritik)"
            elif mn == "call": aciklama = "Fonksiyon Çağrısı (Subroutine)"
            elif mn == "cmp": aciklama = "Karşılaştırma (Compare)"
            elif mn == "test": aciklama = "Mantıksal AND Testi (Sıfır Testi)"
            elif mn == "nop": aciklama = "No Operation (Bypass İçin Boş Geç)"
            elif mn == "ret": aciklama = "Fonksiyondan Geri Dön"
            self.pe_disasm_table.setItem(row, 3, QTableWidgetItem(aciklama))
            
        self.pe_current_row = 0
        self.pe_highlight_row(0)

    def pe_step_over(self):
        if self.pe_state != 2: return
        if self.pe_current_row < len(self.aktif_pe_instructions) - 1:
            self.pe_current_row += 1
            self.pe_highlight_row(self.pe_current_row)
            inst = self.aktif_pe_instructions[self.pe_current_row]
            self.pe_log_ekrani.append(f"[x86 CPU] Adımlanıyor (F8): RIP -> 0x{inst['va']:X} ({inst['mnemonic']} {inst['op_str']})")
            
            # Dinamik Durum Çubuğu Güncellemesi
            mn = inst['mnemonic'].lower()
            if mn in ["jz", "je", "jnz", "jne"]:
                self.pe_status_bar.setText(f"Durum: DURAKLATILDI (Karar Noktası) | Modül: {os.path.basename(self.aktif_pe_yolu)}")
            else:
                self.pe_status_bar.setText(f"Durum: DURAKLATILDI | Modül: {os.path.basename(self.aktif_pe_yolu)}")

    def pe_highlight_row(self, row):
        for r in range(self.pe_disasm_table.rowCount()):
            bg = QColor("#000000") if self.tema_modu == "Hacker" else QColor("#1e293b")
            fg = QColor("#39ff14") if self.tema_modu == "Hacker" else QColor("#f1f5f9")
            if r == row:
                bg = QColor("#eab308")
                fg = QColor("#000000")
            for c in range(self.pe_disasm_table.columnCount()):
                item = self.pe_disasm_table.item(r, c)
                if item:
                    item.setBackground(bg)
                    item.setForeground(fg)
        
        self.pe_disasm_table.selectRow(row)
        if row < len(self.aktif_pe_instructions):
            inst = self.aktif_pe_instructions[row]
            self.lbl_reg_rip.setText(f"0x{inst['va']:08X}")

    def pe_search_strings(self):
        if not self.aktif_pe_data: return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Dize Başvuru Kaynakları (String References)")
        dialog.resize(700, 500)
        
        layout = QVBoxLayout(dialog)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrele:"))
        filter_input = QLineEdit()
        filter_input.setPlaceholderText("Aramak için yazın... (örn: password, key)")
        filter_layout.addWidget(filter_input)
        layout.addLayout(filter_layout)
        
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Dosya Offset", "Uzunluk", "Dize (String)"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        layout.addWidget(table)
        
        strings_found = []
        for match in re.finditer(b'[ -~]{5,}', self.aktif_pe_data):
            s = match.group().decode('ascii', errors='ignore')
            strings_found.append({
                "offset": match.start(),
                "len": len(s),
                "str": s
            })
            if len(strings_found) > 1000:
                break
                
        def populate_table(filter_text=""):
            table.setRowCount(0)
            row_idx = 0
            for item in strings_found:
                if filter_text.lower() in item["str"].lower():
                    table.insertRow(row_idx)
                    table.setItem(row_idx, 0, QTableWidgetItem(f"0x{item['offset']:X}"))
                    table.setItem(row_idx, 1, QTableWidgetItem(str(item["len"])))
                    table.setItem(row_idx, 2, QTableWidgetItem(item["str"]))
                    row_idx += 1
                    if row_idx > 200: break
                    
        populate_table()
        filter_input.textChanged.connect(populate_table)
        
        def on_double_click(row, col):
            offset_str = table.item(row, 0).text()
            self.pe_log_ekrani.append(f"[DEBUGGER] Dize referansı incelendi: Offset {offset_str}")
            dialog.accept()
            
        table.cellDoubleClicked.connect(on_double_click)
        dialog.exec()

    def pe_patch_nop(self):
        row = self.pe_disasm_table.currentRow()
        if row < 0 or not self.aktif_pe_yolu:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir PE dosyası yükleyin ve yama yapılacak satırı seçin.")
            return

        inst = self.aktif_pe_instructions[row]
        # Her byte'ı NOP (0x90) ile değiştirelim
        nop_bytes = [0x90] * inst["size"]
        
        self.patch_adres_deger(inst["offset"], nop_bytes, inst["va"])

    def pe_patch_custom(self):
        row = self.pe_disasm_table.currentRow()
        if row < 0 or not self.aktif_pe_yolu:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir PE dosyası yükleyin ve yama yapılacak satırı seçin.")
            return

        inst = self.aktif_pe_instructions[row]
        text, ok = QLineEdit.getText(self, "Özel Opcode Yama", f"Giriş (Hex biçiminde, boşluklu veya bitişik, örn: 90 90 veya EB 12):\nMevcut boyut: {inst['size']} byte")
        if not ok or not text.strip():
            return

        try:
            # Hex string'i byte listesine çevir
            hex_cleaned = text.replace(" ", "")
            input_bytes = bytearray.fromhex(hex_cleaned)
            
            if len(input_bytes) != inst["size"]:
                QMessageBox.warning(self, "Boyut Uyuşmazlığı", f"Girdiğiniz yama boyutu ({len(input_bytes)} byte) seçtiğiniz talimatın boyutu ile ({inst['size']} byte) tam olarak eşleşmelidir!")
                return
            
            self.patch_adres_deger(inst["offset"], list(input_bytes), inst["va"])
        except Exception as e:
            QMessageBox.critical(self, "Hex Hatası", f"Geçersiz hex formatı: {str(e)}")

    def patch_adres_deger(self, offset, yeni_bytes, va):
        try:
            # Dosyaya yazalım
            with open(self.aktif_pe_yolu, "r+b") as f:
                f.seek(offset)
                f.write(bytearray(yeni_bytes))
            
            self.pe_log_ekrani.append(f"[PATCH] 0x{va:X} adresindeki {len(yeni_bytes)} byte yamanarak yazıldı!")
            QMessageBox.information(self, "Başarılı", f"0x{va:X} adresi başarıyla yamalandı (Dosya güncellendi). Lütfen değişiklikleri görmek için dosyayı yeniden yükleyin.")
            
            # Yeniden yükle
            self.pe_analiz_et(self.aktif_pe_yolu)
        except Exception as e:
            QMessageBox.critical(self, "Patch Hatası", f"Dosyaya yazarken hata oluştu: {str(e)}")

    def closeEvent(self, event):
        """Çarpıya basıldığında tray'e küçültür, tamamen kapatmaz."""
        # DoS thread aktifse güvenli durdur
        if self.dos_thread and self.dos_thread.isRunning():
            self.dos_thread.durdur()
        event.ignore()
        self.hide()

    def _setup_ipc_server(self):
        """Tek örnek IPC sunucusunu başlatır. Başka bir örnekten 'SHOW' mesajı gelince pencereyi öne getirir."""
        self._ipc_server = QLocalServer(self)
        self._ipc_server.newConnection.connect(self._on_ipc_message)
        self._ipc_server.listen("ReiectusSecuritas_IPC")

    def _on_ipc_message(self):
        """Başka bir örnekten gelen bağlantıyı yakalar ve pencereyi öne getirir."""
        socket = self._ipc_server.nextPendingConnection()
        if socket:
            socket.waitForReadyRead(500)
            socket.readAll()  # mesajı temizle
            socket.disconnectFromServer()
        # Pencereyi öne getir
        self.showNormal()
        self.activateWindow()
        self.raise_()


if __name__ == "__main__":
    APP_ID = "ReiectusSecuritas_IPC"
    app = QApplication(sys.argv)

    # Zaten çalışan bir örnek var mı?
    socket = QLocalSocket()
    socket.connectToServer(APP_ID)
    if socket.waitForConnected(500):
        # Evet — mevcut pencereye "SHOW" gönder ve çık
        socket.write(b"SHOW")
        socket.flush()
        socket.disconnectFromServer()
        sys.exit(0)

    # Hayır — ilk örnek, sunucuyu kur
    QLocalServer.removeServer(APP_ID)  # önceki çakılmadan kalan varsa temizle
    p = ReiectusSecuritas()
    p._setup_ipc_server()
    p.show()
    sys.exit(app.exec())