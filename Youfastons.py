import socket
import threading
import socks
import time
import os
import random
import sys
import traceback
import json
import base64
import hashlib
import secrets
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEnginePage, QWebEngineSettings
from PyQt6.QtNetwork import QNetworkProxy

class MilitaryGradeEncryptor:
    @staticmethod
    def generate_key():
        return secrets.token_bytes(32)
    
    @staticmethod
    def derive_key(password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        return key, salt
    
    @staticmethod
    def encrypt_file(filename, password, data):
        try:
            key, salt = MilitaryGradeEncryptor.derive_key(password)
            iv = secrets.token_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(data.encode('utf-8') if isinstance(data, str) else data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(salt + iv + encrypted_data)
            hmac_digest = hmac.digest()
            final_data = salt + iv + hmac_digest + encrypted_data
            with open(filename, 'wb') as f:
                f.write(final_data)
            control_hash = hashlib.sha256(final_data).hexdigest()
            with open(filename + '.x', 'w') as f:
                f.write(control_hash)
            return True
        except Exception as e:
            return False
    
    @staticmethod
    def decrypt_file(filename, password):
        try:
            sig_file = filename + '.x'
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    expected_hash = f.read().strip()
                with open(filename, 'rb') as f:
                    file_data = f.read()
                actual_hash = hashlib.sha256(file_data).hexdigest()
                if actual_hash != expected_hash:
                    return None
            with open(filename, 'rb') as f:
                file_data = f.read()
            if len(file_data) < 64:
                return None
            salt = file_data[:16]
            iv = file_data[16:32]
            hmac_digest = file_data[32:64]
            encrypted_data = file_data[64:]
            key, _ = MilitaryGradeEncryptor.derive_key(password, salt)
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(salt + iv + encrypted_data)
            try:
                hmac.verify(hmac_digest)
            except ValueError:
                return None
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            return None
    
    @staticmethod
    def obfuscate_filename(filename):
        import hashlib
        hash_name = hashlib.sha256(filename.encode()).hexdigest()[:16]
        return f"system_{hash_name}.dat"

class StealthProxyManager:
    def __init__(self, master_key="supersecret_military_key_2024"):
        self.master_key = master_key
        self.encrypted_filename = "IP"
        self.backup_filename = "backup_config.bak"
        
    def save_proxies_stealth(self, proxies_list):
        try:
            proxies_json = json.dumps(proxies_list, ensure_ascii=False)
            garbage = secrets.token_bytes(random.randint(100, 500))
            timestamp = int(time.time())
            data_structure = {
                "version": "2.0",
                "timestamp": timestamp,
                "proxies": proxies_list,
                "metadata": {
                    "encryption": "AES-256-CBC-HMAC-SHA256",
                    "created": datetime.now().isoformat(),
                    "signature": secrets.token_hex(32)
                }
            }
            data_to_encrypt = json.dumps(data_structure, ensure_ascii=False)
            encrypted = MilitaryGradeEncryptor.encrypt_file(
                self.encrypted_filename, 
                self.master_key, 
                data_to_encrypt
            )
            if encrypted:
                return True
        except Exception as e:
            return False
    
    def load_proxies_stealth(self):
        try:
            if not os.path.exists(self.encrypted_filename):
                return []
            decrypted = MilitaryGradeEncryptor.decrypt_file(
                self.encrypted_filename,
                self.master_key
            )
            if decrypted:
                data = json.loads(decrypted)
                if "proxies" in data:
                    if self.check_data_integrity(data):
                        return data["proxies"]
                    else:
                        return data["proxies"]
            return []
        except Exception as e:
            return []
    
    def check_data_integrity(self, data):
        try:
            required_fields = ["version", "timestamp", "proxies", "metadata"]
            for field in required_fields:
                if field not in data:
                    return False
            current_time = int(time.time())
            if current_time - data["timestamp"] > 2592000:
                pass
            for proxy in data["proxies"]:
                if not all(key in proxy for key in ["host", "port"]):
                    return False
            return True
        except:
            return False

class AccountManager:
    def __init__(self):
        self.accounts_file = "youtube_accounts.json"
        self.current_account = None
        self.stealth_encryptor = StealthProxyManager()
        self.accounts = self.load_accounts()
        if self.accounts:
            self.set_current_account(self.accounts[-1])
    
    def load_accounts(self):
        try:
            if os.path.exists(self.accounts_file):
                with open(self.accounts_file, 'r', encoding='utf-8') as f:
                    accounts = json.load(f)
                    return accounts
        except Exception as e:
            pass
        return []
    
    def save_account(self, email, password, cookies=None, session_data=None):
        try:
            account_id = base64.b64encode(email.encode()).decode()[:20]
            account_data = {
                "id": account_id,
                "email": email,
                "password": password,
                "cookies": cookies or [],
                "session_data": session_data or {},
                "created_at": datetime.now().isoformat(),
                "last_used": datetime.now().isoformat()
            }
            existing_index = -1
            for i, acc in enumerate(self.accounts):
                if acc["email"] == email:
                    existing_index = i
                    break
            if existing_index >= 0:
                self.accounts[existing_index] = account_data
            else:
                self.accounts.append(account_data)
            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                json.dump(self.accounts, f, indent=2, ensure_ascii=False)
            self.set_current_account(account_data)
            return True
        except Exception as e:
            return False
    
    def get_accounts(self):
        return self.accounts
    
    def set_current_account(self, account):
        self.current_account = account
    
    def clear_current_account(self):
        self.current_account = None
    
    def get_current_account(self):
        return self.current_account
    
    def has_accounts(self):
        return len(self.accounts) > 0

class LocalProxyStatic:
    def __init__(self, account_manager):
        self.local_host = "127.0.0.1"
        self.local_port = 8110
        self.stealth_manager = StealthProxyManager()
        self.proxy_servers = self.load_proxies_from_file()
        self.static_proxy = None
        self.server = None
        self.running = False
        self.account_manager = account_manager
        if self.proxy_servers:
            self.select_random_proxy()
    
    def select_random_proxy(self):
        if self.proxy_servers:
            self.static_proxy = random.choice(self.proxy_servers)
        else:
            print("Нет доступных прокси для выбора")
    
    def load_proxies_from_file(self):
        proxies = []
        stealth_proxies = self.stealth_manager.load_proxies_stealth()
        if stealth_proxies:
            return stealth_proxies
        filename = "IP.x"
        if not os.path.exists(filename):
            return proxies
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 4:
                            proxy = {
                                "host": parts[0].strip(),
                                "port": int(parts[1].strip()),
                                "user": parts[2].strip(),
                                "pass": parts[3].strip()
                            }
                            proxies.append(proxy)
                        elif len(parts) == 2:
                            proxy = {
                                "host": parts[0].strip(),
                                "port": int(parts[1].strip()),
                                "user": "",
                                "pass": ""
                            }
                            proxies.append(proxy)
            if proxies:
                if self.stealth_manager.save_proxies_stealth(proxies):
                    try:
                        os.remove(filename)
                    except:
                        pass
            return proxies
        except Exception as e:
            return []
    
    def get_proxy_for_domain(self, domain):
        return self.static_proxy

    def get_domain_from_request(self, data):
        try:
            if not data:
                return "unknown-domain"
            lines = data.split(b"\r\n")
            if not lines or not lines[0]:
                return "unknown-domain"
            first_line = lines[0]
            if first_line.startswith(b"CONNECT"):
                parts = first_line.split(b" ")
                if len(parts) >= 2:
                    try:
                        host_port = parts[1].decode()
                        if ":" in host_port:
                            return host_port.split(":")[0]
                        return host_port
                    except UnicodeDecodeError:
                        return "unknown-domain"
            for line in lines:
                if line and line.lower().startswith(b"host:"):
                    try:
                        host = line.split(b":", 1)[1].strip().decode()
                        if ":" in host:
                            return host.split(":")[0]
                        return host
                    except (UnicodeDecodeError, IndexError):
                        return "unknown-domain"
        except Exception as e:
            pass
        return "unknown-domain"

    def forward_data(self, src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            try:
                src.close()
            except:
                pass
            try:
                dst.close()
            except:
                pass

    def handle_client(self, client_sock):
        try:
            request = client_sock.recv(65536)
            if not request:
                client_sock.close()
                return
            domain = self.get_domain_from_request(request)
            first_line = request.split(b"\r\n")[0]
            if first_line.startswith(b"CONNECT"):
                try:
                    host_port = first_line.split(b" ")[1]
                    host, port = host_port.decode().split(":")
                    port = int(port)
                    proxy = self.get_proxy_for_domain(domain)
                    if not proxy:
                        client_sock.send(b"HTTP/1.1 503 No proxies available\r\n\r\n")
                        client_sock.close()
                        return
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"], 
                               True, proxy["user"], proxy["pass"])
                    s.connect((host, port))
                    client_sock.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    threading.Thread(target=self.forward_data, args=(client_sock, s), daemon=True).start()
                    threading.Thread(target=self.forward_data, args=(s, client_sock), daemon=True).start()
                except Exception as e:
                    client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    client_sock.close()
            else:
                try:
                    proxy = self.get_proxy_for_domain(domain)
                    if not proxy:
                        client_sock.send(b"HTTP/1.1 503 No proxies available\r\n\r\n")
                        client_sock.close()
                        return
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"], 
                               True, proxy["user"], proxy["pass"])
                    s.connect((domain, 80))
                    s.sendall(request)
                    response = s.recv(65536)
                    while response:
                        client_sock.send(response)
                        response = s.recv(65536)
                except Exception as e:
                    client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                finally:
                    client_sock.close()
        except Exception as e:
            try:
                client_sock.close()
            except:
                pass

    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.local_host, self.local_port))
            self.server.listen(100)
            self.running = True
            print(f"Локальный прокси запущен на {self.local_host}:{self.local_port}")
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            return True
        except Exception as e:
            return False

    def _run_server(self):
        while self.running:
            try:
                client_sock, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()
            except Exception as e:
                if self.running:
                    time.sleep(0.1)

    def stop(self):
        self.running = False
        if self.server:
            self.server.close()

class BrowserView(QWebEngineView):
    def __init__(self, account_manager, parent=None):
        super().__init__(parent)
        self.account_manager = account_manager
        self.settings().setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, True)
        self.settings().setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, False)
        self.settings().setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, True)
        self.settings().setAttribute(QWebEngineSettings.WebAttribute.AllowGeolocationOnInsecureOrigins, True)
        self.page().fullScreenRequested.connect(self.handle_fullscreen_request)
        self.page().loadFinished.connect(self.on_page_loaded)
        self.login_attempted = False
        self.current_url = ""
        
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_custom_context_menu)
        
        self.login_js = r"""
        function autoLogin(email, password) {
            function findElement(selectors) {
                for (const selector of selectors) {
                    try {
                        if (selector.startsWith('contains(')) {
                            const text = selector.match(/contains\("([^"]+)"\)/)[1];
                            const elements = document.querySelectorAll('button, span, div, a');
                            for (const el of elements) {
                                if (el.textContent && el.textContent.includes(text) && el.offsetParent !== null) {
                                    return el;
                                }
                            }
                        } else {
                            const el = document.querySelector(selector);
                            if (el && el.offsetParent !== null) {
                                return el;
                            }
                        }
                    } catch(e) {}
                }
                return null;
            }
            const emailSelectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[name="username"]',
                'input[name="login"]',
                'input#identifierId',
                'input[autocomplete="username"]',
                'input[type="text"]'
            ];
            const passwordSelectors = [
                'input[type="password"]',
                'input[name="password"]',
                'input[name="pass"]',
                'input[autocomplete="current-password"]'
            ];
            let emailField = findElement(emailSelectors);
            let passwordField = findElement(passwordSelectors);
            if (emailField && passwordField) {
                emailField.value = email;
                emailField.dispatchEvent(new Event('input', { bubbles: true }));
                emailField.dispatchEvent(new Event('change', { bubbles: true }));
                setTimeout(() => {
                    passwordField.value = password;
                    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
                    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
                    setTimeout(() => {
                        const submitButtons = [
                            'button[type="submit"]',
                            'button:contains("Sign in")',
                            'button:contains("Войти")',
                            'button#passwordNext',
                            'contains("Next")',
                            'contains("Далее")',
                            'div[role="button"]'
                        ];
                        const submitBtn = findElement(submitButtons);
                        if (submitBtn) {
                            submitBtn.click();
                            return true;
                        }
                    }, 1000);
                }, 500);
                return true;
            }
            if (emailField && !passwordField) {
                emailField.value = email;
                emailField.dispatchEvent(new Event('input', { bubbles: true }));
                emailField.dispatchEvent(new Event('change', { bubbles: true }));
                setTimeout(() => {
                    const nextButtons = [
                        'button#identifierNext',
                        'div#identifierNext',
                        'button:contains("Next")',
                        'button:contains("Далее")',
                        'contains("Next")',
                        'contains("Далее")',
                        'div[role="button"]'
                    ];
                    const nextBtn = findElement(nextButtons);
                    if (nextBtn) {
                        nextBtn.click();
                        setTimeout(() => {
                            const passwordField2 = findElement(passwordSelectors);
                            if (passwordField2) {
                                passwordField2.value = password;
                                passwordField2.dispatchEvent(new Event('input', { bubbles: true }));
                                passwordField2.dispatchEvent(new Event('change', { bubbles: true }));
                                setTimeout(() => {
                                    const submitButtons2 = [
                                        'button#passwordNext',
                                        'div#passwordNext',
                                        'button:contains("Sign in")',
                                        'button:contains("Войти")',
                                        'contains("Next")',
                                        'contains("Далее")'
                                    ];
                                    const submitBtn2 = findElement(submitButtons2);
                                    if (submitBtn2) {
                                        submitBtn2.click();
                                    }
                                }, 1000);
                            }
                        }, 2000);
                    }
                }, 500);
                return true;
            }
            return false;
        }
        """
    
    def show_custom_context_menu(self, pos):
        context_menu = QMenu(self)
        
        copy_icon = QIcon()
        paste_icon = QIcon()
        reload_icon = QIcon()
        back_icon = QIcon()
        forward_icon = QIcon()
        
        copy_action = QAction("Копировать", self)
        copy_action.triggered.connect(self.copy_to_clipboard)
        copy_action.setIcon(copy_icon)
        context_menu.addAction(copy_action)
        
        paste_action = QAction("Вставить", self)
        paste_action.triggered.connect(self.paste_from_clipboard)
        paste_action.setIcon(paste_icon)
        context_menu.addAction(paste_action)
        
        context_menu.addSeparator()
        
        reload_action = QAction("Обновить", self)
        reload_action.triggered.connect(self.reload_page)
        reload_action.setIcon(reload_icon)
        context_menu.addAction(reload_action)
        
        context_menu.addSeparator()
        
        back_action = QAction("Назад", self)
        back_action.triggered.connect(self.go_back)
        back_action.setEnabled(self.page().history().canGoBack())
        back_action.setIcon(back_icon)
        context_menu.addAction(back_action)
        
        forward_action = QAction("Вперед", self)
        forward_action.triggered.connect(self.go_forward)
        forward_action.setEnabled(self.page().history().canGoForward())
        forward_action.setIcon(forward_icon)
        context_menu.addAction(forward_action)
        
        context_menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #d0d0d0;
                border-radius: 4px;
                padding: 4px;
                font-family: Arial, sans-serif;
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 20px 6px 8px;
                margin: 2px;
                border-radius: 3px;
                color: #333333;
            }
            QMenu::item:selected {
                background-color: #e6f3ff;
                color: #0066cc;
            }
            QMenu::item:disabled {
                color: #999999;
            }
            QMenu::separator {
                height: 1px;
                background-color: #e0e0e0;
                margin: 4px 8px;
            }
        """)
        
        context_menu.exec(self.mapToGlobal(pos))

    def paste_from_clipboard(self):
        self.page().triggerAction(QWebEnginePage.WebAction.Paste)
    
    def copy_to_clipboard(self):
        self.page().triggerAction(QWebEnginePage.WebAction.Copy)
    
    def reload_page(self):
        self.page().triggerAction(QWebEnginePage.WebAction.Reload)
    
    def go_back(self):
        self.page().triggerAction(QWebEnginePage.WebAction.Back)
    
    def go_forward(self):
        self.page().triggerAction(QWebEnginePage.WebAction.Forward)
    
    def handle_fullscreen_request(self, request):
        if request.toggleOn():
            if self.window().isFullScreen():
                request.reject()
            else:
                self.window().showFullScreen()
                request.accept()
        else:
            self.window().showNormal()
            request.accept()
        js_fix = r"""
        if (typeof ytplayer !== 'undefined') {
            ytplayer.config_.args.fullscreen = true;
            ytplayer.config_.args.fs = true;
            document.addEventListener('keydown', function(e) {
                if (e.key === 'f' || e.key === 'F') {
                    const player = document.querySelector('.html5-video-player');
                    if (player) {
                        if (player.classList.contains('ytp-fullscreen')) {
                            player.classList.remove('ytp-fullscreen');
                        } else {
                            player.classList.add('ytp-fullscreen');
                        }
                    }
                }
            });
        }
        document.querySelectorAll('video').forEach(video => {
            video.setAttribute('webkit-playsinline', '');
            video.setAttribute('playsinline', '');
            video.setAttribute('x5-playsinline', '');
            video.setAttribute('x5-video-player-type', 'h5');
            video.setAttribute('x5-video-player-fullscreen', 'true');
            video.setAttribute('x5-video-orientation', 'landscape');
        });
        if (Element && Element.prototype) {
            if (!Element.prototype.requestFullscreen) {
                Element.prototype.requestFullscreen = Element.prototype.webkitRequestFullscreen || 
                                                     Element.prototype.mozRequestFullScreen || 
                                                     Element.prototype.msRequestFullscreen;
            }
            if (!document.exitFullscreen) {
                document.exitFullscreen = document.webkitExitFullscreen || 
                                         document.mozCancelFullScreen || 
                                         document.msExitFullscreen;
            }
            if (!document.fullscreenElement) {
                Object.defineProperty(document, 'fullscreenElement', {
                    get: function() {
                        return document.webkitFullscreenElement || 
                               document.mozFullScreenElement || 
                               document.msFullscreenElement;
                    }
                });
            }
        }
        """
        self.page().runJavaScript(js_fix)
    
    def on_page_loaded(self, ok):
        if ok:
            self.current_url = self.url().toString()
            if 'youtube.com' in self.current_url:
                youtube_fix_js = r"""
                function fixYouTubeFullscreen() {
                    if (Element && Element.prototype) {
                        if (!Element.prototype.requestFullscreen) {
                            Element.prototype.requestFullscreen = Element.prototype.webkitRequestFullscreen || 
                                                                 Element.prototype.mozRequestFullScreen || 
                                                                 Element.prototype.msRequestfullscreen;
                        }
                        if (!document.exitFullscreen) {
                            document.exitFullscreen = document.webkitExitFullscreen || 
                                                     document.mozCancelFullScreen || 
                                                     document.msExitFullscreen;
                        }
                        if (!document.fullscreenElement) {
                            Object.defineProperty(document, 'fullscreenElement', {
                                get: function() {
                                    return document.webkitFullscreenElement || 
                                           document.mozFullScreenElement || 
                                           document.msFullscreenElement;
                                }
                            });
                        }
                    }
                    const fullscreenButtons = document.querySelectorAll('.ytp-fullscreen-button, .ytp-size-button');
                    fullscreenButtons.forEach(btn => {
                        btn.onclick = function(e) {
                            const player = document.querySelector('.html5-video-player');
                            if (player) {
                                if (player.classList.contains('ytp-fullscreen')) {
                                    player.classList.remove('ytp-fullscreen');
                                    if (document.exitFullscreen) {
                                        document.exitFullscreen();
                                    }
                                } else {
                                    player.classList.add('ytp-fullscreen');
                                    if (player.requestFullscreen) {
                                        player.requestFullscreen();
                                    }
                                }
                                e.stopPropagation();
                                return false;
                            }
                        };
                    });
                    const iframes = document.querySelectorAll('iframe');
                    iframes.forEach(iframe => {
                        iframe.setAttribute('allowfullscreen', '');
                        iframe.setAttribute('webkitallowfullscreen', '');
                        iframe.setAttribute('mozallowfullscreen', '');
                    });
                    const videos = document.querySelectorAll('video');
                    videos.forEach(video => {
                        video.setAttribute('playsinline', '');
                        video.setAttribute('webkit-playsinline', '');
                        video.autoplay = true;
                        video.muted = true;
                    });
                    if (typeof ytplayer !== 'undefined') {
                        ytplayer.config_.args.fullscreen = true;
                        ytplayer.config_.args.fs = true;
                        ytplayer.config_.args.autoplay = 1;
                    }
                    return true;
                }
                fixYouTubeFullscreen();
                const observer = new MutationObserver(fixYouTubeFullscreen);
                observer.observe(document.body, { childList: true, subtree: true });
                setInterval(fixYouTubeFullscreen, 2000);
                """
                self.page().runJavaScript(youtube_fix_js)
            current_account = self.account_manager.get_current_account()
            if current_account:
                is_login_page = any(x in self.current_url for x in [
                    'accounts.google.com', 
                    'youtube.com/signin', 
                    'login',
                    'signin',
                    'auth',
                    'AccountLoginInfo'
                ])
                is_youtube_home = 'youtube.com' in self.current_url and not any(x in self.current_url for x in ['signin', 'login', 'auth'])
                if is_login_page and not self.login_attempted:
                    js_code = f"""
                    {self.login_js}
                    document.body.style.opacity = '0';
                    document.body.style.transition = 'opacity 0.3s';
                    setTimeout(() => {{
                        const result = autoLogin("{current_account['email']}", "{current_account['password']}");
                        if (result) {{
                            document.body.innerHTML = '<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);font-size:20px;color:black;">Вход в аккаунт...</div>';
                            document.body.style.opacity = '1';
                        }} else {{
                            document.body.style.opacity = '1';
                        }}
                    }}, 1000);
                    """
                    self.page().runJavaScript(js_code)
                    self.login_attempted = True
                    QTimer.singleShot(5000, self.check_login_status)
                elif is_youtube_home and self.login_attempted:
                    self.login_attempted = False
    
    def check_login_status(self):
        if self.login_attempted:
            if self.current_url and 'accounts.google.com' in self.current_url:
                current_account = self.account_manager.get_current_account()
                if current_account:
                    js_code = f"""
                    {self.login_js}
                    setTimeout(() => {{
                        autoLogin("{current_account['email']}", "{current_account['password']}");
                    }}, 1000);
                    """
                    self.page().runJavaScript(js_code)
                    QTimer.singleShot(3000, lambda: self.redirect_to_youtube_if_needed())
    
    def redirect_to_youtube_if_needed(self):
        if self.current_url and 'accounts.google.com' in self.current_url:
            self.setUrl(QUrl("https://www.youtube.com"))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.account_manager = AccountManager()
        self.proxy = LocalProxyStatic(self.account_manager)
        self.auto_login_enabled = True
        self.initUI()
        if self.account_manager.has_accounts():
            self.auto_start_proxy()
        else:
            QTimer.singleShot(500, self.show_account_input_dialog)
    
    def show_account_input_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Сохранить аккаунт")
        dialog.setFixedSize(400, 250)
        
        self.set_dialog_icon(dialog)
        
        layout = QVBoxLayout(dialog)
        title_label = QLabel("Введите данные аккаунта YouTube")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title_label)
        email_layout = QHBoxLayout()
        email_label = QLabel("Email:")
        email_label.setFixedWidth(80)
        self.email_input = QLineEdit()
        email_layout.addWidget(email_label)
        email_layout.addWidget(self.email_input)
        layout.addLayout(email_layout)
        password_layout = QHBoxLayout()
        password_label = QLabel("Пароль:")
        password_label.setFixedWidth(80)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        buttons_layout = QHBoxLayout()
        self.save_button = QPushButton("Сохранить и продолжить")
        self.save_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.save_button.clicked.connect(lambda: self.save_and_continue(dialog))
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.close)
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addWidget(self.cancel_button)
        layout.addLayout(buttons_layout)
        dialog.setModal(True)
        dialog.exec()
    
    def set_dialog_icon(self, dialog):
        try:
            icon_path = "icon.png"
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
                dialog.setWindowIcon(icon)
            else:
                pixmap = QPixmap(64, 64)
                pixmap.fill(QColor("transparent"))
                painter = QPainter(pixmap)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                painter.setBrush(QColor("#3498db"))
                painter.setPen(QPen(QColor("#2980b9"), 2))
                painter.drawEllipse(10, 20, 40, 30)
                painter.drawEllipse(20, 10, 30, 25)
                painter.setBrush(QColor("#e74c3c"))
                painter.setPen(QPen(QColor("#c0392b"), 2))
                painter.drawRect(25, 30, 15, 20)
                painter.drawEllipse(28, 25, 8, 8)
                painter.setPen(QPen(QColor("#27ae60"), 3))
                painter.drawLine(40, 40, 45, 45)
                painter.drawLine(45, 45, 55, 35)
                painter.end()
                icon = QIcon(pixmap)
                dialog.setWindowIcon(icon)
        except Exception as e:
            pass
    
    def save_and_continue(self, dialog):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        if not email or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля!")
            return
        if self.account_manager.save_account(email, password):
            dialog.accept()
            QTimer.singleShot(500, self.auto_start_proxy)
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось сохранить аккаунт!")
    
    def auto_start_proxy(self):
        if not self.proxy.proxy_servers:
            QMessageBox.critical(self, "Ошибка", 
                               "Не найдены прокси в файле IP.x!\n" +
                               "Добавьте прокси в файл и перезапустите программу.\n\n" +
                               "Формат:\n" +
                               "host:port:user:pass\n" +
                               "или\n" +
                               "host:port")
            return
        if not self.proxy.static_proxy:
            self.proxy.select_random_proxy()
        if self.proxy.start():
            self.setup_browser_proxy()
            QTimer.singleShot(1000, self.open_youtube)
        else:
            print("Не удалось автоматически запустить прокси")
    
    def open_youtube(self):
        current_account = self.account_manager.get_current_account()
        if current_account:
            loading_html = """
            <html>
            <head>
                <style>
                    body {
                        background: white;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        font-family: Arial, sans-serif;
                    }
                    .loading {
                        text-align: center;
                    }
                    .spinner {
                        border: 8px solid #f3f3f3;
                        border-top: 8px solid #3498db;
                        border-radius: 50%;
                        width: 60px;
                        height: 60px;
                        animation: spin 1s linear infinite;
                        margin: 0 auto 20px auto;
                    }
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    .info {
                        margin-top: 30px;
                        font-size: 14px;
                        color: #333;
                        text-align: center;
                        line-height: 1.5;
                    }
                    .telegram-link {
                        color: #0088cc;
                        text-decoration: none;
                        font-weight: bold;
                    }
                    .telegram-link:hover {
                        text-decoration: underline;
                    }
                    .creator {
                        margin-top: 5px;
                        font-size: 12px;
                        color: #666;
                    }
                </style>
            </head>
            <body>
                <div class="loading">
                    <div class="spinner"></div>
                    <h2>Выполняется вход в аккаунт...</h2>
                    <p>Подождите несколько секунд</p>
                    <div class="info">
                        <div>Telegram канал: 
                            <a href="https://t.me/Stronikson" class="telegram-link" target="_blank">
                                https://t.me/Stronikson
                            </a>
                        </div>
                        <div class="creator">Создатель: Kironetix</div>
                    </div>
                </div>
            </body>
            </html>
            """
            self.browser.setHtml(loading_html, QUrl("about:blank"))
            QTimer.singleShot(5000, lambda: self.browser.setUrl(QUrl("https://accounts.google.com/ServiceLogin?service=youtube&uilel=3&passive=true&continue=https%3A%2F%2Fwww.youtube.com%2Fsignin%3Faction_handle_signin%3Dtrue%26app%3Ddesktop%26hl%3Den%26next%3D%252F&hl=en")))
        else:
            self.browser.setUrl(QUrl("https://www.youtube.com"))
    
    def initUI(self):
        self.setWindowTitle("Youfastons")
        self.set_icon()
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: white;
            }
        """)
        self.browser = BrowserView(self.account_manager)
        self.setCentralWidget(self.browser)
        self.menuBar().setVisible(False)
    
    def set_icon(self):
        try:
            icon_path = "icon.png"
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
                self.setWindowIcon(icon)
            else:
                self.create_fallback_icon()
        except Exception as e:
            self.create_fallback_icon()
    
    def create_fallback_icon(self):
        try:
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor("transparent"))
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(QColor("#3498db"))
            painter.setPen(QPen(QColor("#2980b9"), 2))
            painter.drawEllipse(10, 20, 40, 30)
            painter.drawEllipse(20, 10, 30, 25)
            painter.setBrush(QColor("#e74c3c"))
            painter.setPen(QPen(QColor("#c0392b"), 2))
            painter.drawRect(25, 30, 15, 20)
            painter.drawEllipse(28, 25, 8, 8)
            painter.setPen(QPen(QColor("#27ae60"), 3))
            painter.drawLine(40, 40, 45, 45)
            painter.drawLine(45, 45, 55, 35)
            painter.end()
            icon = QIcon(pixmap)
            self.setWindowIcon(icon)
        except Exception as e:
            pass
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
    
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.close()
        elif event.key() == Qt.Key.Key_F:
            if not self.isFullScreen():
                self.showFullScreen()
            else:
                self.showNormal()
        elif event.key() == Qt.Key.Key_F5:
            self.browser.reload()
        else:
            super().keyPressEvent(event)
    
    def setup_browser_proxy(self):
        try:
            proxy = QNetworkProxy()
            proxy.setType(QNetworkProxy.ProxyType.HttpProxy)
            proxy.setHostName("127.0.0.1")
            proxy.setPort(8110)
            QNetworkProxy.setApplicationProxy(proxy)
        except Exception as e:
            pass
    
    def closeEvent(self, event):
        if self.proxy.running:
            self.proxy.stop()
        event.accept()

class AccountInputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Сохранить аккаунт")
        self.setFixedSize(400, 250)
        self.initUI()
    
    def initUI(self):
        layout = QVBoxLayout(self)
        
        self.set_dialog_icon()
        
        title_label = QLabel("Введите данные аккаунта YouTube")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title_label)
        email_layout = QHBoxLayout()
        email_label = QLabel("Email:")
        email_label.setFixedWidth(80)
        self.email_input = QLineEdit()
        email_layout.addWidget(email_label)
        email_layout.addWidget(self.email_input)
        layout.addLayout(email_layout)
        password_layout = QHBoxLayout()
        password_label = QLabel("Пароль:")
        password_label.setFixedWidth(80)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        buttons_layout = QHBoxLayout()
        self.save_button = QPushButton("Сохранить и продолжить")
        self.save_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.save_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self.save_button)
        buttons_layout.addWidget(self.cancel_button)
        layout.addLayout(buttons_layout)
    
    def set_dialog_icon(self):
        try:
            icon_path = "icon.png"
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
                self.setWindowIcon(icon)
            else:
                pixmap = QPixmap(64, 64)
                pixmap.fill(QColor("transparent"))
                painter = QPainter(pixmap)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                painter.setBrush(QColor("#3498db"))
                painter.setPen(QPen(QColor("#2980b9"), 2))
                painter.drawEllipse(10, 20, 40, 30)
                painter.drawEllipse(20, 10, 30, 25)
                painter.setBrush(QColor("#e74c3c"))
                painter.setPen(QPen(QColor("#c0392b"), 2))
                painter.drawRect(25, 30, 15, 20)
                painter.drawEllipse(28, 25, 8, 8)
                painter.setPen(QPen(QColor("#27ae60"), 3))
                painter.drawLine(40, 40, 45, 45)
                painter.drawLine(45, 45, 55, 35)
                painter.end()
                icon = QIcon(pixmap)
                self.setWindowIcon(icon)
        except Exception as e:
            pass
    
    def get_data(self):
        return {
            "email": self.email_input.text().strip(),
            "password": self.password_input.text().strip()
        }

def handle_exception(exc_type, exc_value, exc_traceback):
    error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    print(f"Uncaught exception: {error_msg}")
    if QApplication.instance():
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setText("Произошла критическая ошибка")
        msg.setInformativeText(str(exc_value))
        msg.setWindowTitle("Ошибка")
        msg.setDetailedText(error_msg)
        msg.exec()
    else:
        print("No QApplication instance available to show error message")
    sys.exit(1)

def restart_application():
    os.execl(sys.executable, sys.executable, *sys.argv)

def main():
    sys.excepthook = handle_exception
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    font = QFont("Monospace", 10)
    font.setStyleHint(QFont.StyleHint.TypeWriter)
    app.setFont(font)
    try:
        accounts_file = "youtube_accounts.json"
        if not os.path.exists(accounts_file):
            dialog = AccountInputDialog()
            if dialog.exec() == QDialog.DialogCode.Accepted:
                data = dialog.get_data()
                if data["email"] and data["password"]:
                    temp_account = [{
                        "id": base64.b64encode(data["email"].encode()).decode()[:20],
                        "email": data["email"],
                        "password": data["password"],
                        "cookies": [],
                        "session_data": {},
                        "created_at": datetime.now().isoformat(),
                        "last_used": datetime.now().isoformat()
                    }]
                    with open(accounts_file, 'w', encoding='utf-8') as f:
                        json.dump(temp_account, f, indent=2, ensure_ascii=False)
                else:
                    sys.exit(0)
            else:
                sys.exit(0)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        handle_exception(type(e), e, e.__traceback__)

if __name__ == "__main__":
    main()
