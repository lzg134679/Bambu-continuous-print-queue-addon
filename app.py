import os
import json
import socket
import ssl
import re
import configparser
import zipfile
import xml.etree.ElementTree as ET
import random
import string
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
try:
    import tkinter as _tk
    from tkinter import filedialog as _filedialog
except Exception:
    _tk = None
    _filedialog = None
import threading
import webbrowser
import time
import requests
import shutil
import tempfile
import uuid
import urllib.parse

# 获取当前文件所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 运行时数据根目录：可通过环境变量 APP_DATA_DIR 指定（容器挂载卷时使用）；默认使用代码所在目录
data_root = os.path.abspath(os.environ.get('APP_DATA_DIR', current_dir))
os.makedirs(data_root, exist_ok=True)


def data_path(*parts):
    """在数据根目录下拼接路径，避免在只读代码目录写入导致异常"""
    return os.path.join(data_root, *parts)

# 确保关键目录存在（容器首次启动时自动创建）
for required_dir in ['3mf', 'temp', 'tempDownload']:
    os.makedirs(data_path(required_dir), exist_ok=True)


def normalize_base_url(url):
    """规范化 Home Assistant 或其他外部服务的基础 URL：去掉尾部的 '/'，避免拼接 /api/... 时出现双斜杠或 404。"""
    if not url:
        return url
    return url.rstrip('/')

app = Flask(__name__, template_folder=current_dir, static_folder=current_dir)

# 默认配置
DEFAULT_CONFIG = {
    'ftp': {
        'host': '',
        'port': '990',
        'user': 'bblp',
        'password': '',
        'path': '/cache'
    },
    'homeassistant': {
        'url': '',
        'token': '',
        'printer_entity': '',
        'notify_entity': '',
        'ams_count': '4'  #ams数量，无需修改此配置
    }
}

# 本地文件默认路径配置
DEFAULT_CONFIG.setdefault('local', {})
DEFAULT_CONFIG['local'].setdefault('path', '')

# 全局变量用于存储上传进度
upload_progress = {
    'current_file': None,
    'progress': 0,
    'total_files': 0,
    'current_file_index': 0,
    'status': 'idle',
    'message': ''
}

# 全局变量用于存储下载进度
download_progress = {
    'current_file': None,
    'progress': 0,
    'total_files': 0,
    'current_file_index': 0,
    'status': 'idle',
    'message': '',
    'downloaded_bytes': 0,
    'total_bytes': 0,
    'current_file_progress': 0,
    'current_file_downloaded': 0,
    'current_file_total': 0,
    # 最近成功保存到 tempDownload 的文件名（前端用于触发浏览器保存）
    'last_saved': None,
    'last_saved_url': None
}

download_cancel_flag = False
current_download_client = None
upload_sessions = {}

class ConfigManager:
    def __init__(self, config_file=None):
        # 配置文件默认放在可写的数据目录下，避免容器中代码目录只读导致写入失败
        self.config_file = config_file or data_path('config.ini')
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file, encoding='utf-8')
        else:
            # 创建默认配置
            self.config.read_dict(DEFAULT_CONFIG)
            self.save_config()
    
    def save_config(self):
        """保存配置文件"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)
    
    def get_ftp_config(self):
        """获取FTP配置"""
        try:
            return {
                'host': self.config.get('ftp', 'host', fallback=DEFAULT_CONFIG['ftp']['host']),
                'port': int(self.config.get('ftp', 'port', fallback=DEFAULT_CONFIG['ftp']['port'])),
                'user': self.config.get('ftp', 'user', fallback=DEFAULT_CONFIG['ftp']['user']),
                'password': self.config.get('ftp', 'password', fallback=DEFAULT_CONFIG['ftp']['password']),
                'path': self.config.get('ftp', 'path', fallback=DEFAULT_CONFIG['ftp']['path'])
            }
        except:
            return DEFAULT_CONFIG['ftp']

    def update_ftp_config(self, host, port, user, password, path):
        """更新FTP配置"""
        if not self.config.has_section('ftp'):
            self.config.add_section('ftp')
        
        self.config.set('ftp', 'host', host)
        self.config.set('ftp', 'port', str(port))
        self.config.set('ftp', 'user', user)
        self.config.set('ftp', 'password', password)
        self.config.set('ftp', 'path', path)
        self.save_config()
    
    def get_ha_config(self):
        """获取Home Assistant配置"""
        try:
            return {
                'url': self.config.get('homeassistant', 'url', fallback=DEFAULT_CONFIG['homeassistant']['url']),
                'token': self.config.get('homeassistant', 'token', fallback=DEFAULT_CONFIG['homeassistant']['token']),
                'printer_entity': self.config.get('homeassistant', 'printer_entity', fallback=DEFAULT_CONFIG['homeassistant']['printer_entity']),
                'notify_entity': self.config.get('homeassistant', 'notify_entity', fallback=DEFAULT_CONFIG['homeassistant'].get('notify_entity', '')),
            }
        except:
            return DEFAULT_CONFIG['homeassistant']
    
    def update_ha_config(self, url, token, printer_entity, notify_entity=None):
        """更新Home Assistant配置"""
        if not self.config.has_section('homeassistant'):
            self.config.add_section('homeassistant')
        
        self.config.set('homeassistant', 'url', url)
        self.config.set('homeassistant', 'token', token)
        self.config.set('homeassistant', 'printer_entity', printer_entity)
        # 保存通知文本实体配置（可选）
        self.config.set('homeassistant', 'notify_entity', notify_entity or '')
        self.save_config()

    def get_server_port(self):
        """获取服务器端口，优先从配置文件读取，失败则返回默认5000"""
        try:
            # 端口改用环境变量或固定默认值，不再写入 config.ini，仍兼容已有配置文件
            return int(self.config.get('server', 'port', fallback='5000'))
        except Exception:
            return 5000

config_manager = ConfigManager()

class SimpleFTPSClient:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.control_sock = None
        self.data_sock = None
        self.is_connected = False
        self.is_logged_in = False
        self.current_path = None
        
    def connect(self):
        """建立连接和SSL"""
        try:
            if self.is_connected and self.control_sock:
                # 检查连接是否仍然有效
                try:
                    self.control_sock.send(b"NOOP\r\n")
                    self._recv_response()
                    return True, "连接已存在"
                except:
                    # 连接已断开，需要重新连接
                    self.is_connected = False
                    if self.control_sock:
                        self.control_sock.close()
            
            # 创建控制连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(180)
            sock.connect((self.host, self.port))
            
            # 升级到SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.control_sock = context.wrap_socket(sock, server_hostname=self.host)
            
            # 设置更长的超时时间
            self.control_sock.settimeout(180)
            
            # 读取欢迎消息
            welcome = self._recv_response()
            print(f"{welcome}，连接到打印机成功")
            
            self.is_connected = True
            return True, "成功"
        except Exception as e:
            print(f"\n连接错误: {e}")
            self.is_connected = False
            return False, f"连接错误: {e}"
    
    def login(self):
        """登录FTP服务器"""
        try:
            # 发送用户名
            self._send_command(f"USER {self.user}")
            user_response = self._recv_response()
            # 发送密码
            self._send_command(f"PASS {self.password}")
            pass_response = self._recv_response()
            self.is_logged_in = "230" in pass_response
            return self.is_logged_in, pass_response
        except Exception as e:
            print(f"\n登录错误: {e}")
            self.is_logged_in = False
            return False, f"登录错误: {e}"
    
    def prepare_upload_environment(self, path):
        """准备上传环境：确保连接、登录和切换到目标目录"""
        try:
            # 强制检查连接状态，而不是仅仅检查标志位
            if self.is_connected and self.control_sock:
                try:
                    # NOOP命令测试连接是否有效
                    self._send_command("NOOP")
                    response = self._recv_response()
                    if "200" not in response:
                        print(f"FTP连接已失效")
                        raise Exception("连接已失效")
                except:
                    # 连接已断开，重置状态
                    self.is_connected = False
                    self.is_logged_in = False
                    if self.control_sock:
                        try:
                            self.control_sock.close()
                        except:
                            pass
                        self.control_sock = None
            
            # 重新建立连接（如果需要）
            if not self.is_connected:
                success, message = self.connect()
                if not success:
                    return False, message
            
            # 重新登录（如果需要）
            if not self.is_logged_in:
                success, message = self.login()
                if not success:
                    return False, message
            
            # 切换到目标目录
            if self.current_path != path:
                success, message = self.change_directory(path)
                if not success:
                    return False, message
                self.current_path = path
            
            return True, "环境准备完成"
        except Exception as e:
            return False, f"准备上传环境失败: {e}"
    
    def change_directory(self, path):
        """改变当前工作目录到指定路径"""
        try:
            self._send_command(f"CWD {path}")
            response = self._recv_response()
            # 250表示目录更改成功
            success = "250" in response
            if success:
                self.current_path = path
            return success, response
        except Exception as e:
            print(f"\n切换目录错误: {e}")
            return False, f"切换目录错误: {e}"
    
    def get_file_list(self, path=None):
        """获取服务器文件列表"""
        try:
            # 准备环境
            if path:
                success, msg = self.prepare_upload_environment(path)
            else:
                success, msg = self.prepare_upload_environment(self.current_path or "/")
            
            if not success:
                return False, msg
            
            # 进入被动模式
            self._send_command("PASV")
            pasv_response = self._recv_response()
            
            # 解析PASV响应获取数据连接信息
            data_host, data_port = self._parse_pasv_response(pasv_response)
            if not data_host or not data_port:
                return False, "无法解析PASV响应"
            
            # 建立数据连接
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(30)
            data_sock.connect((data_host, data_port))
            
            # 升级数据连接到SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.data_sock = context.wrap_socket(data_sock, server_hostname=self.host)
            
            # 发送LIST命令获取详细文件列表
            self._send_command("LIST")
            list_response = self._recv_response()
            print(f"获取文件列表")
            
            # 接收数据
            data = self._recv_data()
            
            # 关闭数据连接
            self.data_sock.close()
            
            # 读取传输完成响应
            transfer_response = self._recv_response()
            
            # 解析文件列表
            files = self._parse_list_response(data)
            return True, files
            
        except Exception as e:
            print(f"\n获取文件列表错误: {e}")
            return False, f"获取文件列表错误: {e}"
    
    def _parse_list_response(self, data):
        """解析LIST命令返回的文件列表"""
        files = []
        lines = data.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # 解析LIST输出格式，例如:
            # -rw-r--r-- 1 owner group 12345 Jan 01 12:00 filename.3mf
            # drwxr-xr-x 2 owner group 4096 Jan 01 12:00 directory_name
            parts = line.split()
            if len(parts) < 9:
                continue
                
            # 检查是文件还是目录
            is_directory = parts[0].startswith('d')
            is_file = parts[0].startswith('-')
            
            if is_file or is_directory:
                try:
                    # 文件名是最后一部分
                    filename = ' '.join(parts[8:])
                    
                    # 跳过特殊文件
                    if filename in ['.', '..']:
                        continue
                    
                    # 文件大小
                    size = int(parts[4]) if is_file else 0
                    
                    # 解析日期和时间
                    month = parts[5]
                    day = parts[6]
                    time_str = parts[7]
                    
                    # 构建修改时间（假设是当前年份）
                    current_year = datetime.now().year
                    try:
                        modified_time = datetime.strptime(f"{current_year} {month} {day} {time_str}", "%Y %b %d %H:%M")
                    except:
                        modified_time = datetime.now()
                    
                    files.append({
                        'name': filename,
                        'size': size,
                        'size_formatted': format_file_size(size),
                        'modified': modified_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'directory' if is_directory else 'file'
                    })
                    
                except (ValueError, IndexError) as e:
                    print(f"解析文件信息错误: {e}, 行: {line}")
                    continue
        
        return files
    
    def upload_file(self, local_file_path, remote_file_name=None, remote_path=None, retry_count=3, progress_callback=None):
        """上传文件到FTP服务器"""
        for attempt in range(retry_count):
            try:
                # 准备上传环境
                if remote_path:
                    success, msg = self.prepare_upload_environment(remote_path)
                else:
                    success, msg = self.prepare_upload_environment(self.current_path or "/cache")
                
                if not success:
                    if attempt < retry_count - 1:
                        print(f"连接异常，尝试重新连接... ({attempt + 1}/{retry_count})")
                        self.is_connected = False
                        self.is_logged_in = False
                        continue
                    return False, msg
                
                # 如果没有指定远程文件名，使用本地文件名
                if remote_file_name is None:
                    remote_file_name = os.path.basename(local_file_path)
                
                # 检查本地文件是否存在
                if not os.path.exists(local_file_path):
                    print(f"本地文件不存在: {local_file_path}")
                    return False, f"本地文件不存在: {local_file_path}"
                
                # 进入被动模式
                self._send_command("PASV")
                pasv_response = self._recv_response()
                
                # 解析PASV响应获取数据连接信息
                data_host, data_port = self._parse_pasv_response(pasv_response)
                if not data_host or not data_port:
                    if attempt < retry_count - 1:
                        print(f"无法解析PASV响应，重试... ({attempt + 1}/{retry_count})")
                        continue
                    return False, "无法解析PASV响应"
                
                # 建立数据连接
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.settimeout(180)
                data_sock.connect((data_host, data_port))
                
                # 升级数据连接到SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.data_sock = context.wrap_socket(data_sock, server_hostname=self.host)
                self.data_sock.settimeout(180)
                
                # 发送STOR命令
                self._send_command(f"STOR {remote_file_name}")
                stor_response = self._recv_response()
                
                # 检查STOR命令是否被接受
                if not stor_response.startswith("150"):
                    self.data_sock.close()
                    if attempt < retry_count - 1:
                        print(f"STOR命令被拒绝，重试... ({attempt + 1}/{retry_count})")
                        continue
                    return False, f"STOR命令被拒绝: {stor_response}"

                # 读取本地文件并上传
                file_size = os.path.getsize(local_file_path)
                uploaded_bytes = 0
                with open(local_file_path, 'rb') as f:
                    while True:
                        chunk = f.read(15 * 1024)
                        if not chunk:
                            break
                        self.data_sock.send(chunk)
                        uploaded_bytes += len(chunk)
                        progress = (uploaded_bytes / file_size) * 100
                        
                        # 调用进度回调函数
                        if progress_callback:
                            progress_callback(remote_file_name, progress, uploaded_bytes, file_size)

                # 关闭数据连接
                self.data_sock.close()
                
                # 读取传输完成响应
                transfer_response = self._recv_response()
                
                # 226表示传输成功完成
                success = "226" in transfer_response
                if success:
                    print(f"{remote_file_name} 上传成功")
                    return True, transfer_response
                elif attempt < retry_count - 1:
                    print(f"传输未完成，重试... ({attempt + 1}/{retry_count})")
                    continue
                else:
                    return False, transfer_response
                    
            except ssl.SSLError as e:
                print(f"\nSSL错误 (尝试 {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    # 重置连接状态，下次重试会重新建立连接
                    self.is_connected = False
                    self.is_logged_in = False
                    if self.control_sock:
                        try:
                            self.control_sock.close()
                        except:
                            pass
                        self.control_sock = None
                    print("SSL错误，重新连接...")
                    continue
                else:
                    return False, f"SSL错误: {e}"
            except Exception as e:
                print(f"\n上传文件错误 (尝试 {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    # 对于其他错误也尝试重新连接
                    self.is_connected = False
                    self.is_logged_in = False
                    if self.control_sock:
                        try:
                            self.control_sock.close()
                        except:
                            pass
                        self.control_sock = None
                    print("上传错误，重新连接...")
                    continue
                else:
                    return False, f"上传文件错误: {e}"
        
        return False, "上传失败，已达到最大重试次数"
    
    def download_file(self, remote_filename, local_path=None, remote_path=None, progress_callback=None):
        """从FTP服务器下载文件"""
        try:
            global download_cancel_flag, current_download_client
            current_download_client = self
            download_cancel_flag = False
            # 准备环境
            if remote_path:
                success, msg = self.prepare_upload_environment(remote_path)
            else:
                success, msg = self.prepare_upload_environment(self.current_path or "/")
            
            if not success:
                return False, msg
            
            # 如果没有指定本地路径，使用程序目录下的 tempDownload
            if local_path is None:
                local_path = data_path('tempDownload', remote_filename)
            
            # 确保下载目录存在
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # 进入被动模式
            self._send_command("PASV")
            pasv_response = self._recv_response()
            
            # 解析PASV响应获取数据连接信息
            data_host, data_port = self._parse_pasv_response(pasv_response)
            if not data_host or not data_port:
                return False, "无法解析PASV响应"
            
            # 建立数据连接
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(180)
            data_sock.connect((data_host, data_port))
            
            # 升级数据连接到SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.data_sock = context.wrap_socket(data_sock, server_hostname=self.host)
            self.data_sock.settimeout(180)
            
            # 发送RETR命令
            self._send_command(f"RETR {remote_filename}")
            retr_response = self._recv_response()
            
            # 检查RETR命令是否被接受
            if not retr_response.startswith("150"):
                self.data_sock.close()
                return False, f"RETR命令被拒绝: {retr_response}"
            
            # 接收数据并写入本地文件
            downloaded_bytes = 0
            try:
                with open(local_path, 'wb') as f:
                    while True:
                        # 检查是否请求取消
                        if download_cancel_flag:
                            raise Exception("下载已被用户取消")
                        
                        chunk = self.data_sock.recv(15 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded_bytes += len(chunk)
                        
                        # 调用进度回调函数
                        if progress_callback:
                            progress_callback(remote_filename, downloaded_bytes)
                            
            except Exception as e:
                # 如果是取消导致的异常，清理文件
                if "取消" in str(e) or download_cancel_flag:
                    try:
                        os.remove(local_path)
                        return False, f"下载已被用户取消"
                    except:
                        pass
                    raise e
            
            finally:
                # 关闭数据连接
                try:
                    self.data_sock.close()
                except:
                    pass
            
            # 读取传输完成响应
            transfer_response = self._recv_response()
            
            # 226表示传输成功完成
            success = "226" in transfer_response
            if success:
                print(f"{remote_filename} 下载成功")
                return True, local_path
            else:
                return False, transfer_response
                
        except Exception as e:
            print(f"下载文件错误: {e}")
            return False, f"下载文件错误: {e}"
    
    def delete_file(self, filename, path=None):
        """删除服务器上的文件"""
        try:
            # 准备环境
            if path:
                success, msg = self.prepare_upload_environment(path)
            else:
                success, msg = self.prepare_upload_environment(self.current_path or "/")
            
            if not success:
                return False, msg
            
            # 发送删除命令
            self._send_command(f"DELE {filename}")
            response = self._recv_response()
            print(f"删除成功")
            
            # 250表示删除成功
            success = "250" in response
            return success, response
            
        except Exception as e:
            print(f"删除文件错误: {e}")
            return False, f"删除文件错误: {e}"
    
    def get_current_directory(self):
        """获取当前工作目录"""
        try:
            self._send_command("PWD")
            response = self._recv_response()
            # PWD响应格式: 257 "/current/path"
            print(f"当前目录: {response}")
            match = re.search(r'"(.*)"', response)
            if match:
                return match.group(1)
            return "/"
        except Exception as e:
            print(f"获取当前目录错误: {e}")
            return "/"
    
    def quit(self):
        """断开连接"""
        try:
            if self.control_sock:
                self._send_command("QUIT")
                quit_response = self._recv_response()
        except:
            pass
        finally:
            if self.control_sock:
                self.control_sock.close()
            self.control_sock = None
            self.data_sock = None
            self.is_connected = False
            self.is_logged_in = False
            self.current_path = None
    
    def _send_command(self, command):
        """发送命令到服务器"""
        self.control_sock.send(f"{command}\r\n".encode())
    
    def _recv_response(self):
        """接收服务器响应"""
        response = ""
        while True:
            try:
                chunk = self.control_sock.recv(4096).decode()
                response += chunk
                if "\r\n" in chunk:
                    break
            except socket.timeout:
                break
        return response.strip()
    
    def _recv_data(self):
        """接收数据"""
        data = ""
        while True:
            try:
                chunk = self.data_sock.recv(4096).decode()
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return data
    
    def _parse_pasv_response(self, response):
        """解析PASV响应"""
        # PASV响应格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        match = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', response)
        if match:
            h1, h2, h3, h4, p1, p2 = map(int, match.groups())
            host = f"{h1}.{h2}.{h3}.{h4}"
            port = (p1 << 8) + p2
            return host, port
        return None, None

def is_running_in_docker():
    """获取当前运行方式是否为docker容器"""
    if os.path.exists('/.dockerenv'):
        return True
    try:
        with open('/proc/self/cgroup', 'r', encoding='utf-8') as f:
            content = f.read()
        return 'docker' in content or 'kubepods' in content
    except Exception:
        return False


def open_browser(port, host=None):
    """自动打开浏览器"""
    target_host = host or '127.0.0.1'
    url = f"http://{target_host}:{port}"
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"自动打开浏览器失败: {e}")

def get_3mf_files(folder_path=None):
    """获取指定文件夹内的 .3mf 文件信息。若未提供 folder_path，则默认使用 '3mf' 文件夹（向后兼容）。"""
    files = []

    # 如果未提供路径，使用默认的3mf文件夹
    if not folder_path:
        folder_path = data_path('3mf')

    # 展开用户与环境变量并去除首尾空白
    folder_path = os.path.expanduser(os.path.expandvars(folder_path)).strip()

    # 如果传入的是相对路径，则基于当前程序目录解析
    if not os.path.isabs(folder_path):
        folder_path = os.path.join(data_root, folder_path)

    # 如果目录不存在，直接返回空列表（不自动创建任意传入目录）
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        return files

    try:
        for filename in os.listdir(folder_path):
            if filename.lower().endswith('.3mf'):
                file_path = os.path.join(folder_path, filename)
                try:
                    stat = os.stat(file_path)
                    files.append({
                        'name': filename,
                        'size': stat.st_size,
                        'size_formatted': format_file_size(stat.st_size),
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'path': file_path
                    })
                except Exception:
                    # 忽略无法访问的文件
                    continue
    except Exception:
        return files

    return files

def format_file_size(size_bytes):
    """格式化文件大小"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.2f} {size_names[i]}"

def test_ftp_connection(host, port, user, password, path):
    """测试FTP连接"""
    client = SimpleFTPSClient(host, port, user, password)
    
    # 测试连接
    success, message = client.connect()
    if not success:
        return False, message
    
    # 测试登录
    success, message = client.login()
    if not success:
        client.quit()
        return False, message
    
    # 测试目录切换
    success, message = client.change_directory(path)
    if not success:
        client.quit()
        return False, f"无法切换到目录 {path}: {message}"
    
    client.quit()
    return True, "连接测试成功！"

def extract_3mf_file(file_path, extract_to):
    """解压3mf文件到指定目录"""
    try:
        if os.path.exists(extract_to):
            shutil.rmtree(extract_to)
        os.makedirs(extract_to)
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        return True, "解压成功"
    except Exception as e:
        print(f"\n解压失败: {str(e)}")
        return False, f"解压失败: {str(e)}"

def get_3mf_preview_image(extract_path):
    """获取3mf文件的预览图"""
    preview_path = os.path.join(extract_path, "Metadata", "plate_1.png")
    if os.path.exists(preview_path):
        return preview_path
    return None

def get_3mf_filament_info(extract_path):
    """获取3mf文件的耗材信息"""
    try:
        # 读取project_settings.config
        settings_path = os.path.join(extract_path, "Metadata", "project_settings.config")
        if not os.path.exists(settings_path):
            return None, "project_settings.config文件不存在"
        
        with open(settings_path, 'r', encoding='utf-8') as f:
            settings_content = f.read()
        
        # 解析JSON
        settings_data = json.loads(settings_content)
        filament_types = settings_data.get("filament_type", [])
        filament_settings_ids = settings_data.get("filament_settings_id", [])
        
        # 初始化数组，-1表示未使用
        filament_array = [-1] * len(filament_types)
        
        # 读取slice_info.config
        slice_info_path = os.path.join(extract_path, "Metadata", "slice_info.config")
        if not os.path.exists(slice_info_path):
            return filament_array, "slice_info.config文件不存在，无法获取实际使用的耗材"
        
        tree = ET.parse(slice_info_path)
        root = tree.getroot()
        
        # 查找所有filament元素
        for filament in root.findall(".//filament"):
            filament_id = int(filament.get("id"))-1
            filament_type = filament.get("type")
            filament_color = filament.get("color", "#FFFFFF")
            filament_settings_id = ""
            if filament_id <= len(filament_settings_ids):
                filament_settings_id = filament_settings_ids[filament_id]
            
            # 确保ID在数组范围内
            if 0 <= filament_id <= len(filament_array):
                filament_array[filament_id] = {
                    'type': filament_type,
                    'color': filament_color,
                    'id': filament_id,
                    'settings_id': filament_settings_id
                }
        
        return filament_array, "成功获取耗材信息"
    except Exception as e:
        print(f"\n获取耗材信息失败: {str(e)}")
        return None, f"获取耗材信息失败: {str(e)}"

def get_filament_mapping(printer_entity, ams_count, ha_url, ha_token):
    """获取AMS和外挂料盘的耗材信息"""
    filament_mapping = {}
    
    try:
        ha_url = normalize_base_url(ha_url)
        headers = {
            "Authorization": f"Bearer {ha_token}",
            "Content-Type": "application/json"
        }
        
        # 获取外挂料盘
        external_spool_entity = f"sensor.{printer_entity}_externalspool_external_spool"
        response = requests.get(f"{ha_url}/api/states/{external_spool_entity}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('attributes', {})
            filament_mapping['external'] = {
                'type': attributes.get('type', 'Unknown'),
                'color': attributes.get('color', '#FFFFFF'),
                'name': '外挂料盘'
            }
        
        # 获取AMS各槽位
        for ams_index in range(1, ams_count + 1):
            for tray_index in range(1, 5):  # 每个AMS有4个槽位
                tray_entity = f"sensor.{printer_entity}_ams_{ams_index}_tray_{tray_index}"
                response = requests.get(f"{ha_url}/api/states/{tray_entity}", headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get('attributes', {})
                    
                    # 计算映射值: (ams_index-1)*4 + (tray_index-1)
                    mapping_value = (ams_index - 1) * 4 + (tray_index - 1)
                    
                    filament_mapping[str(mapping_value)] = {
                        'type': attributes.get('type', 'Unknown'),
                        'color': attributes.get('color', '#FFFFFF'),
                        'name': f"AMS{ams_index}-槽位{tray_index}"
                    }
        
        return filament_mapping, "成功获取耗材映射"
    except Exception as e:
        print(f"\n获取耗材映射失败: {str(e)}")
        return {}, f"获取耗材映射失败: {str(e)}"

def get_device_id(printer_entity, ha_url, ha_token):
    """通过模板API获取设备ID"""
    try:
        ha_url = normalize_base_url(ha_url)
        headers = {
            "Authorization": f"Bearer {ha_token}",
            "Content-Type": "application/json"
        }
        
        # 使用模板API获取设备ID
        template = f"{{{{ device_id('sensor.{printer_entity}_print_status') }}}}"
        data = {
            "template": template
        }
        
        response = requests.post(f"{ha_url}/api/template", headers=headers, json=data, timeout=10)
        
        if response.status_code == 200:
            device_id = response.text.strip()
            if device_id and device_id != "None":
                return device_id, "成功获取设备ID"
            else:
                return None, "模板返回为空，可能实体不存在"
        else:
            return None, f"请求失败: {response.status_code} - {response.text}"
            
    except Exception as e:
        print(f"\n获取设备ID失败: {str(e)}")
        return None, f"获取设备ID失败: {str(e)}"

def generate_webhook_id():
    """生成16位的webhook ID"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

def generate_automation_yaml(print_queue, webhook_id, printer_entity, device_id):
    """生成自动化YAML配置"""
    
    automation = {
        "alias": f"00-连续打印队列-{printer_entity}",
        "description": f"{printer_entity}自动队列打印-{int(time.time())}",
        "triggers": [
            {
                "trigger": "webhook",
                "allowed_methods": ["POST", "PUT"],
                "local_only": False,
                "webhook_id": webhook_id
            }
        ],
        "conditions": [
            {
                "condition": "or",
                "conditions": [
                    {
                        "condition": "state",
                        "entity_id": f"sensor.{printer_entity}_print_status",
                        "state": "finish"
                    },
                    {
                        "condition": "state",
                        "entity_id": f"sensor.{printer_entity}_print_status",
                        "state": "idle"
                    }
                ]
            }
        ],
        "actions": [],
        "mode": "single"
    }
    
    # 计算总打印任务数（考虑副本数）
    total_jobs = 0
    for file_config in print_queue:
        if isinstance(file_config, dict):
            try:
                copies = int(file_config.get('copies', 1))
            except Exception:
                copies = 1
        else:
            copies = 1
        total_jobs += copies

    # 为每个打印文件生成动作
    for file_config in print_queue:
        copies = file_config.get('copies', 1) if isinstance(file_config, dict) else 1

        # 计算盘号：优先使用 file_config 中的 plate 或 plate_index 字段，
        # 其次尝试从 gcode_file、preview_url、file_path 中提取
        plate_number = None
        if isinstance(file_config, dict):
            plate_number = file_config.get('plate') or file_config.get('plate_index')
            gcode_file = file_config.get('gcode_file') or file_config.get('gcode') or file_config.get('gcodeFile')
            preview_url_cfg = file_config.get('preview_url') or file_config.get('preview')
            file_path_cfg = file_config.get('file_path') or file_config.get('path')
        else:
            gcode_file = None
            preview_url_cfg = None
            file_path_cfg = None

        if not plate_number and gcode_file:
            m = re.search(r'plate_(\d+)\.gcode', str(gcode_file))
            if m:
                try:
                    plate_number = int(m.group(1))
                except:
                    plate_number = None

        # 如果仍未找到，尝试从 preview_url 中提取（例如 Metadata/plate_2.png）
        if not plate_number and preview_url_cfg:
            m2 = re.search(r'plate_(\d+)\.(png|gcode)', str(preview_url_cfg))
            if m2:
                try:
                    plate_number = int(m2.group(1))
                except:
                    plate_number = None

        # 再尝试从 file_path_cfg 或 filename 字段中提取
        if not plate_number and file_path_cfg:
            m3 = re.search(r'plate_(\d+)\.(gcode|3mf|png)', str(file_path_cfg))
            if m3:
                try:
                    plate_number = int(m3.group(1))
                except:
                    plate_number = None

        if not plate_number and isinstance(file_config, dict):
            fn = file_config.get('filename') or file_config.get('name')
            if fn:
                m4 = re.search(r'plate_(\d+)\.(gcode|3mf|png)', str(fn))
                if m4:
                    try:
                        plate_number = int(m4.group(1))
                    except:
                        plate_number = None

        # 默认盘号为1，保证兼容性
        if not plate_number:
            plate_number = 1

        for copy_index in range(copies):
            # 等待打印完成
            automation["actions"].append({
                "repeat": {
                    "until": [
                        {
                            "condition": "or",
                            "conditions": [
                                {
                                    "condition": "state",
                                    "entity_id": f"sensor.{printer_entity}_print_status",
                                    "state": "finish"
                                },
                                {
                                    "condition": "state",
                                    "entity_id": f"sensor.{printer_entity}_print_status",
                                    "state": "idle"
                                }
                            ]
                        }
                    ],
                    "sequence": [
                        {
                            "delay": {
                                "hours": 0,
                                "minutes": 0,
                                "seconds": 15,
                                "milliseconds": 0
                            }
                        }
                    ]
                }
            })

            # 打印文件（注：plate 使用计算得到的 plate_number）
            ams_mapping = file_config.get('ams_mapping', []) if isinstance(file_config, dict) else []
            use_ams = any(mapping >= 0 for mapping in ams_mapping)

            # 格式化 ams_mapping 为逗号分隔字符串（无空格），例如 "-1,2,-1"
            if use_ams:
                try:
                    ams_mapping_str = ','.join(str(int(x)) for x in ams_mapping)
                except Exception:
                    ams_mapping_str = ','.join(str(x) for x in ams_mapping)
            else:
                ams_mapping_str = "0"

            automation["actions"].append({
                "action": "bambu_lab.print_project_file",
                "metadata": {},
                "data": {
                    "device_id": device_id,
                    "plate": plate_number,
                    "timelapse": file_config.get('timelapse', False) if isinstance(file_config, dict) else False,
                    "bed_leveling": file_config.get('bed_leveling', True) if isinstance(file_config, dict) else True,
                    "flow_cali": file_config.get('flow_cali', True) if isinstance(file_config, dict) else True,
                    "vibration_cali": False,
                    "layer_inspect": False,
                    "use_ams": use_ams,
                    "ams_mapping": ams_mapping_str,
                    "filepath": f"file:///sdcard/cache/{file_config.get('filename')}" if isinstance(file_config, dict) else f"file:///sdcard/cache/{file_config}"
                },
                "enabled": True,  # 调试时可以禁用打印动作
            })

            # 延迟1分钟
            automation["actions"].append({
                "delay": {
                    "hours": 0,
                    "minutes": 1,
                    "seconds": 0,
                    "milliseconds": 0
                }
            })

    # 根据配置决定是否添加通知文本动作
    try:
        ha_conf = config_manager.get_ha_config()
        notify_entity = (ha_conf.get('notify_entity') or '').strip()
    except Exception:
        notify_entity = ''

    if notify_entity:
        # 从 printer_entity 中提取显示名称
        try:
            display_name = printer_entity.split('_', 1)[0] if printer_entity else ''
        except Exception:
            display_name = printer_entity or ''

        message = f"{display_name}的{total_jobs}个队列打印任务已完成"

        automation["actions"].append({
            "action": "text.set_value",
            "metadata": {},
            "data": {
                "value": message
            },
            "target": {
                "entity_id": notify_entity
            }
        })
    
    return automation

def update_upload_progress(current_file, progress, current_file_index, total_files, status='uploading', message=''):
    """更新上传进度信息"""
    global upload_progress
    upload_progress = {
        'current_file': current_file,
        'progress': progress,
        'current_file_index': current_file_index,
        'total_files': total_files,
        'status': status,
        'message': message
    }

def update_download_progress(current_file, progress, current_file_index, total_files, downloaded_bytes, total_bytes, status='downloading', message=''):
    """更新下载进度信息"""
    global download_progress
    download_progress.update({
        'current_file': current_file,
        'progress': progress,
        'current_file_index': current_file_index,
        'total_files': total_files,
        'downloaded_bytes': downloaded_bytes,
        'total_bytes': total_bytes,
        'status': status,
        'message': message
    })

def create_automation_in_ha(automation_config, ha_url, ha_token):
    """在Home Assistant中创建自动化"""
    try:
        ha_url = normalize_base_url(ha_url)
        headers = {
            "Authorization": f"Bearer {ha_token}",
            "Content-Type": "application/json"
        }

        automation_id = automation_config["alias"].replace(" ", "_").replace("-", "_").lower()
        url = f"{ha_url}/api/config/automation/config/{automation_id}"
        data = {
            "alias": automation_config["alias"],
            "description": automation_config["description"],
            "trigger": automation_config["triggers"],
            "condition": automation_config["conditions"],
            "action": automation_config["actions"],
            "mode": automation_config["mode"]
        }
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code in [200, 201]:
            print(f"自动化创建成功: {automation_config['alias']}")
            return True

    except Exception as e:
        print(f"创建自动化时出错: {str(e)}")
        return False

def update_upload_session(upload_id, status, message, current_file=None, current_index=0, total_files=0, progress=0):
    """更新上传会话进度"""
    if upload_id in upload_sessions:
        upload_sessions[upload_id].update({
            'status': status,
            'message': message,
            'current_file': current_file or upload_sessions[upload_id].get('current_file', ''),
            'current_file_index': current_index,
            'total_files': total_files or upload_sessions[upload_id].get('total_files', 0),
            'progress': progress
        })
    else:
        # 如果会话不存在，创建新的会话
        upload_sessions[upload_id] = {
            'status': status,
            'message': message,
            'current_file': current_file or '',
            'current_file_index': current_index,
            'total_files': total_files,
            'progress': progress
        }

@app.route('/')
def index():
    """主页面"""
    # 将程序运行目录传递给前端作为默认本地路径
    return render_template('index.html', current_dir=data_root)

@app.route('/api/files')
def get_files():
    """获取本地文件列表API"""
    try:
        target_dir = data_path('3mf')
        os.makedirs(target_dir, exist_ok=True)
        files = get_3mf_files(target_dir)
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/upload-local-3mf', methods=['POST'])
def upload_local_3mf():
    """上传3mf文件到程序目录下的3mf文件夹"""
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': '未找到上传的文件'}), 400

        files = request.files.getlist('files')
        if not files:
            return jsonify({'success': False, 'error': '未选择文件'}), 400

        target_dir = data_path('3mf')
        os.makedirs(target_dir, exist_ok=True)

        saved_files = []
        rejected_files = []

        for file in files:
            raw_name = file.filename or ''
            # 仅保留文件名，允许中文，去掉路径分隔符
            filename = os.path.basename(raw_name.replace('\\', '/')).strip()

            # 仅接受3mf文件
            if not filename.lower().endswith('.3mf'):
                rejected_files.append(raw_name)
                continue

            # 避免空文件名
            if not filename:
                rejected_files.append(raw_name)
                continue

            base, ext = os.path.splitext(filename)
            final_name = filename
            counter = 1
            while os.path.exists(os.path.join(target_dir, final_name)):
                final_name = f"{base}_{counter}{ext}"
                counter += 1

            file.save(os.path.join(target_dir, final_name))
            saved_files.append(final_name)

        if not saved_files:
            return jsonify({'success': False, 'error': '仅支持上传3mf文件'}), 400

        response = {'success': True, 'saved': saved_files}
        if rejected_files:
            response['rejected'] = rejected_files

        return jsonify(response)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/delete-local-file', methods=['POST'])
def delete_local_file():
    """删除程序目录3mf文件夹中的文件"""
    try:
        data = request.get_json() or {}
        filename = (data.get('filename') or '').strip()

        if not filename:
            return jsonify({'success': False, 'error': '文件名不能为空'}), 400

        safe_name = os.path.basename(filename.replace('\\', '/')).strip()
        target_dir = data_path('3mf')
        file_path = os.path.join(target_dir, safe_name)

        if not os.path.isfile(file_path):
            return jsonify({'success': False, 'error': '文件不存在'}), 404

        os.remove(file_path)
        return jsonify({'success': True, 'message': f'文件 {safe_name} 删除成功'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/pick-folder', methods=['GET'])
def pick_folder():
    """在服务器端弹出本地文件夹选择对话框，返回选中的路径（仅在本地运行有效）"""
    try:
        if _tk is None or _filedialog is None:
            return jsonify({'success': False, 'error': '服务器不支持图形文件对话框'})

        root = _tk.Tk()
        root.withdraw()
        # 确保对话框在最前
        try:
            root.attributes('-topmost', True)
        except Exception:
            pass
        folder = _filedialog.askdirectory()
        root.destroy()

        if folder:
            return jsonify({'success': True, 'path': folder})
        else:
            return jsonify({'success': False, 'path': ''})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/server-files', methods=['GET', 'POST'])
def get_server_files():
    """获取服务器文件列表API（支持GET和POST）"""
    try:
        config = config_manager.get_ftp_config()
        client = SimpleFTPSClient(config['host'], config['port'], config['user'], config['password'])
        
        # 连接服务器
        success, message = client.connect()
        if not success:
            return jsonify({'success': False, 'error': message})
        
        # 登录
        success, message = client.login()
        if not success:
            client.quit()
            return jsonify({'success': False, 'error': message})
        
        # 获取目标路径
        target_path = config['path']  # 默认使用配置的路径
        
        # 如果是POST请求，尝试从请求体中获取路径
        if request.method == 'POST':
            try:
                data = request.get_json()
                if data and 'path' in data:
                    target_path = data['path']
            except:
                pass  # 如果解析失败，使用默认路径

        # 切换到目标目录
        success, message = client.change_directory(target_path)
        if not success:
            client.quit()
            return jsonify({'success': False, 'error': message})
        
        # 获取当前目录
        current_path = client.current_path
        
        # 获取文件列表
        success, result = client.get_file_list(current_path)
        if not success:
            client.quit()
            return jsonify({'success': False, 'error': result})
        
        client.quit()
        return jsonify({
            'success': True, 
            'files': result,
            'current_path': current_path
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    """配置管理API"""
    if request.method == 'GET':
        # 获取配置
        ftp_config = config_manager.get_ftp_config()
        ha_config = config_manager.get_ha_config()
        return jsonify({'success': True, 'ftp_config': ftp_config, 'ha_config': ha_config})
    else:
        # 更新配置
        try:
            data = request.json
            config_manager.update_ftp_config(
                data.get('host'),
                data.get('port'),
                data.get('user'),
                data.get('password'),
                data.get('path')
            )
            config_manager.update_ha_config(
                data.get('ha_url'),
                data.get('ha_token'),
                data.get('printer_entity'),
                data.get('notify_entity')
            )
            return jsonify({'success': True, 'message': '配置保存成功'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})


@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """测试连接API"""
    try:
        data = request.json
        success, message = test_ftp_connection(
            data.get('host'),
            data.get('port'),
            data.get('user'),
            data.get('password'),
            data.get('path')
        )
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/test-ha-connection', methods=['POST'])
def test_ha_connection():
    """测试Home Assistant连接API"""
    try:
        data = request.json
        ha_url = data.get('ha_url')
        ha_token = data.get('ha_token')
        printer_entity = data.get('printer_entity')
        
        if not ha_url or not ha_token or not printer_entity:
            return jsonify({'success': False, 'error': 'Home Assistant配置不完整'})
        
        # 测试获取设备ID
        device_id, message = get_device_id(printer_entity, ha_url, ha_token)
        
        if device_id:
            return jsonify({'success': True, 'message': f'与Home Assistant通讯成功'})
        else:
            return jsonify({'success': False, 'error': f'Home Assistant连接失败: {message}'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete-server-file', methods=['POST'])
def delete_server_file():
    """删除服务器文件API"""
    try:
        data = request.json
        filename = data.get('filename')
        path = data.get('path', '/')
        config = config_manager.get_ftp_config()
        
        client = SimpleFTPSClient(config['host'], config['port'], config['user'], config['password'])
        
        # 准备环境并删除文件
        success, message = client.prepare_upload_environment(path)
        if not success:
            client.quit()
            return jsonify({'success': False, 'error': message})
        
        # 删除文件
        success, message = client.delete_file(filename)
        client.quit()
        
        if success:
            return jsonify({'success': True, 'message': f'文件 {filename} 删除成功'})
        else:
            return jsonify({'success': False, 'error': f'删除失败: {message}'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download-server-file', methods=['POST'])
def download_server_file():
    """下载服务器文件API"""
    try:
        data = request.json
        filename = data.get('filename')
        path = data.get('path', '/')
        total_bytes = data.get('total_bytes', 0)  # 前端传入的文件总大小
        
        if not filename:
            return jsonify({'success': False, 'error': '文件名不能为空'})

        global download_progress
        download_progress.update({
            'current_file': None,
            'progress': 0,
            'total_files': 0,
            'current_file_index': 0,
            'status': 'idle',
            'message': '',
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'current_file_progress': 0,
            'current_file_downloaded': 0,
            'current_file_total': 0
        })

        config = config_manager.get_ftp_config()
        client = SimpleFTPSClient(config['host'], config['port'], config['user'], config['password'])
        # 准备环境
        success, message = client.prepare_upload_environment(path)
        if not success:
            client.quit()
            return jsonify({'success': False, 'error': message})
        
        # 下载文件到程序目录下的 tempDownload
        download_dir = data_path('tempDownload')
        os.makedirs(download_dir, exist_ok=True)
        local_path = os.path.join(download_dir, filename)
        # 如果前端未提供 total_bytes（0），尝试从服务器获取文件大小以便计算进度
        if not total_bytes or total_bytes == 0:
            try:
                # 尝试获取当前目录的文件列表并查找文件大小
                success_list, files_list = client.get_file_list(path)
                if success_list and files_list:
                    for f in files_list:
                        if f.get('name') == filename:
                            total_bytes = f.get('size', 0) or 0
                            break
            except Exception:
                # 忽略错误，后续仍然会使用 total_bytes=0
                total_bytes = total_bytes or 0

        # 初始化下载进度
        download_progress = {
            'current_file': filename,
            'progress': 0,
            'total_files': 1,
            'current_file_index': 0,
            'status': 'downloading',
            'message': f'开始下载文件 {filename}',
            'downloaded_bytes': 0,
            'total_bytes': total_bytes,
            'current_file_progress': 0,
            'current_file_downloaded': 0,
            'current_file_total': total_bytes
        }
        
        # 定义进度回调函数
        def progress_callback(current_file, downloaded_bytes):
            progress = (downloaded_bytes / total_bytes) * 100 if total_bytes > 0 else 0

            update_download_progress(
                current_file=current_file,
                progress=progress,
                current_file_index=0,
                total_files=1,
                downloaded_bytes=downloaded_bytes,
                total_bytes=total_bytes,
                status='downloading',
                message=f'{current_file}: {progress:.1f}% ({format_file_size(downloaded_bytes)} / {format_file_size(total_bytes)})'
            )
        
        # 下载文件
        success, result = client.download_file(filename, local_path, progress_callback=progress_callback)
        client.quit()
        
        if success:
            update_download_progress(
                current_file=filename,
                progress=100,
                current_file_index=1,
                total_files=1,
                downloaded_bytes=total_bytes,
                total_bytes=total_bytes,
                status='success',
                message=f'文件 {filename} 下载成功'
            )
            
            # 在单独的线程中延迟删除临时文件
            def delayed_delete(file_path, delay_seconds=60):
                time.sleep(delay_seconds)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"删除临时文件失败 {file_path}: {e}")
            threading.Thread(target=delayed_delete, args=(local_path,), daemon=True).start()
            
            # 标记已保存并提供外部可访问的 URL，方便前端直接触发浏览器下载
            encoded_name = urllib.parse.quote(filename)
            file_url = f'/tempDownload/{urllib.parse.quote(filename)}'

            download_progress['last_saved'] = filename
            download_progress['last_saved_url'] = file_url

            return jsonify({
                'success': True,
                'message': f'文件 {filename} 下载成功',
                'file_path': local_path,
                'file_url': file_url
            })
        else:
            update_download_progress(
                current_file=filename,
                progress=0,
                current_file_index=0,
                total_files=1,
                downloaded_bytes=0,
                total_bytes=total_bytes,
                status='error',
                message=f'下载失败: {result}'
            )
            return jsonify({'success': False, 'error': f'下载失败: {result}'})
            
    except Exception as e:
        update_download_progress(
            current_file='',
            progress=0,
            current_file_index=0,
            total_files=0,
            downloaded_bytes=0,
            total_bytes=0,
            status='error',
            message=f'下载失败: {str(e)}'
        )
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/batch-download-server-files', methods=['POST'])
def batch_download_server_files():
    """批量下载服务器文件API"""
    try:
        data = request.json
        files = data.get('files', [])
        
        if not files or len(files) == 0:
            return jsonify({'success': False, 'error': '文件列表不能为空'})
        
        global download_progress
        download_progress.update({
            'current_file': None,
            'progress': 0,
            'total_files': 0,
            'current_file_index': 0,
            'status': 'idle',
            'message': '',
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'current_file_progress': 0,
            'current_file_downloaded': 0,
            'current_file_total': 0
        })

        config = config_manager.get_ftp_config()
        
        # 初始化下载进度
        total_files = len(files)
        download_progress = {
            'current_file': None,
            'progress': 0,
            'total_files': total_files,
            'current_file_index': 0,
            'status': 'starting',
            'message': f'准备开始下载 {total_files} 个文件...',
            'downloaded_bytes': 0,
            'total_bytes': sum(file.get('size', 0) for file in files),
            'current_file_progress': 0,
            'current_file_downloaded': 0,
            'current_file_total': 0
        }
        
        downloaded_files = []
        download_dir = data_path('tempDownload')
        os.makedirs(download_dir, exist_ok=True)
        
        for index, file_info in enumerate(files):
            filename = file_info.get('name')
            total_bytes = file_info.get('size', 0)
            file_path = file_info.get('path', '/')
            # 更新当前文件信息
            download_progress['current_file'] = filename
            download_progress['current_file_index'] = index
            download_progress['current_file_total'] = total_bytes
            download_progress['current_file_downloaded'] = 0
            download_progress['current_file_progress'] = 0
            download_progress['status'] = 'downloading'
            download_progress['message'] = f'开始下载文件 {filename} ({index+1}/{total_files})'

            # 为每个文件使用新的 FTP 连接（避免复用同一连接导致的问题）
            client = SimpleFTPSClient(config['host'], config['port'], config['user'], config['password'])
            try:
                success, message = client.connect()
                if not success:
                    downloaded_files.append({'name': filename, 'path': None, 'success': False, 'error': f'连接失败: {message}'})
                    print(f"连接失败: {message}")
                    continue

                success, message = client.login()
                if not success:
                    downloaded_files.append({'name': filename, 'path': None, 'success': False, 'error': f'登录失败: {message}'})
                    client.quit()
                    continue

                # 切换到文件所在目录
                success, message = client.change_directory(file_path)
                if not success:
                    downloaded_files.append({'name': filename, 'path': None, 'success': False, 'error': f'切换目录失败: {message}'})
                    client.quit()
                    continue

                local_path = os.path.join(download_dir, filename)

                # 定义进度回调函数
                def progress_callback(current_file, downloaded_bytes):
                    progress = (downloaded_bytes / total_bytes) * 100 if total_bytes > 0 else 0

                    # 更新当前文件进度
                    download_progress['current_file_downloaded'] = downloaded_bytes
                    download_progress['current_file_progress'] = progress

                    # 计算总体进度：已完成文件数 *100 + 当前文件进度
                    overall_progress = ((index * 100) + progress) / total_files
                    download_progress['progress'] = overall_progress
                    download_progress['downloaded_bytes'] = sum(f['size'] for f in files[:index]) + downloaded_bytes
                    download_progress['message'] = (
                        f'{filename}: {progress:.1f}% '
                        f'({format_file_size(downloaded_bytes)} / {format_file_size(total_bytes)}) '
                        f'- 文件 {index+1}/{total_files}'
                    )

                # 下载文件（每个文件独立连接）
                success, result = client.download_file(filename, local_path, progress_callback=progress_callback)

                if success:
                    downloaded_files.append({'name': filename, 'path': local_path, 'success': True})

                    # 标记当前文件已保存到 tempDownload，并通知前端触发浏览器保存
                    encoded_name = urllib.parse.quote(filename)
                    download_progress['current_file_progress'] = 100
                    download_progress['downloaded_bytes'] = sum(f['size'] for f in files[:index+1])
                    download_progress['progress'] = ((index + 1) * 100) / total_files
                    download_progress['message'] = f'文件 {filename} 下载成功 ({index+1}/{total_files})'
                    download_progress['last_saved'] = filename
                    download_progress['last_saved_url'] = f'/tempDownload/{urllib.parse.quote(filename)}'

                    # 在单独线程中延迟删除临时文件（与单文件行为一致）
                    def delayed_delete(file_path, delay_seconds=30):
                        time.sleep(delay_seconds)
                        try:
                            if os.path.exists(file_path):
                                os.remove(file_path)
                        except Exception as e:
                            print(f"删除临时文件失败 {file_path}: {e}")
                    threading.Thread(target=delayed_delete, args=(local_path,), daemon=True).start()
                else:
                    downloaded_files.append({'name': filename, 'path': None, 'success': False, 'error': result})
                    print(f"下载文件 {filename} 失败: {result}")

                # 等待短暂延迟再处理下一个文件
                time.sleep(1)
            finally:
                try:
                    client.quit()
                except:
                    pass
        
        client.quit()
        
        # 所有文件下载完成
        download_progress.update({
            'current_file': None,
            'progress': 100,
            'current_file_index': total_files,
            'status': 'success',
            'message': f'所有文件下载完成，共{total_files}个文件',
            'last_saved': None,
            'last_saved_url': None
        })
        
        return jsonify({
            'success': True,
            'message': f'批量下载完成，成功{total_files}个文件',
            'files': downloaded_files
        })
        
    except Exception as e:
        download_progress.update({
            'current_file': '',
            'progress': 0,
            'current_file_index': 0,
            'total_files': 0,
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'status': 'error',
            'message': f'批量下载失败: {str(e)}'
        })
        return jsonify({'success': False, 'error': str(e)})

@app.route('/tempDownload/<path:filename>')
def download_file(filename):
    """提供下载文件访问（使用程序目录下的 tempDownload）"""
    download_dir = data_path('tempDownload')
    return send_from_directory(download_dir, filename, as_attachment=True)


@app.route('/api/runtime-info')
def runtime_info():
    """返回运行时信息：程序目录和主机 URL 等，供前端使用绝对路径请求文件（在单文件打包时有用）"""
    try:
        host_url = request.host_url if request else ''
    except Exception:
        host_url = ''

    info = {
        'current_dir': os.path.abspath(data_root),
        'code_dir': os.path.abspath(current_dir),
        'host_url': host_url
    }
    return jsonify(info)

@app.route('/api/cancel-download', methods=['POST'])
def cancel_download():
    """取消下载API"""
    global download_cancel_flag, current_download_client, download_progress
    
    try:
        download_cancel_flag = True
        download_progress.update({
            'current_file': None,
            'progress': 0,
            'total_files': 0,
            'current_file_index': 0,
            'status': 'cancelled',
            'message': '下载已取消',
            'downloaded_bytes': 0,
            'total_bytes': 0,
            'current_file_progress': 0,
            'current_file_downloaded': 0,
            'current_file_total': 0
        })
        
        # 如果存在当前下载客户端，尝试关闭连接
        if current_download_client:
            try:
                current_download_client.quit()
                print("已中断下载连接")
            except Exception as e:
                print(f"关闭下载连接时出错: {e}")
            finally:
                current_download_client = None
        
        return jsonify({'success': True, 'message': '下载已取消'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze-3mf', methods=['POST'])
def analyze_3mf():
    """分析3MF文件API"""
    try:
        data = request.json
        file_path = data.get('file_path')
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({'success': False, 'error': '文件不存在'})
        
        # 创建临时解压目录（程序目录下的 temp）
        file_name = os.path.basename(file_path)
        temp_dir = data_path('temp', file_name.replace('.3mf', ''))
        
        # 解压文件
        success, message = extract_3mf_file(file_path, temp_dir)
        if not success:
            return jsonify({'success': False, 'error': message})
        # 读取 model_settings.config，获取每个 plate 的 gcode_file 值并校验只有一个非空
        model_settings_path = os.path.join(temp_dir, 'Metadata', 'model_settings.config')
        selected_gcode = None
        selected_plate = None
        try:
            if os.path.exists(model_settings_path):
                tree = ET.parse(model_settings_path)
                root = tree.getroot()

                plate_records = []
                for plate in root.findall('.//plate'):
                    plater_id = None
                    gcode_file_value = ''
                    for meta in plate.findall('metadata'):
                        k = meta.get('key')
                        v = meta.get('value', '')
                        if k == 'plater_id':
                            try:
                                plater_id = int(v)
                            except:
                                plater_id = None
                        if k == 'gcode_file':
                            gcode_file_value = (v or '').strip()
                    plate_records.append({'plater_id': plater_id, 'gcode_file': gcode_file_value})

                # 统计非空 gcode_file
                non_empty = [p for p in plate_records if p.get('gcode_file')]
                if len(non_empty) != 1:
                    # 如果不是恰好一个非空，返回错误给前端以展示错误弹窗
                    return jsonify({'success': False, 'error': '请确保导出的3mf文件为单盘切片'})
                selected = non_empty[0]
                selected_gcode = selected.get('gcode_file')
                selected_plate = selected.get('plater_id')
        except Exception as e:
            print(f"读取 model_settings.config 失败: {e}")

        # 确保选中的 gcode_file 存在或根据盘号构建预览图路径
        preview_url = None
        preview_path = None
        if selected_gcode:
            # 将 gcode 文件名的扩展替换为 png
            png_rel = os.path.splitext(selected_gcode)[0] + '.png'
            preview_path = os.path.join(temp_dir, png_rel)
            if os.path.exists(preview_path):
                preview_url = f"/temp/{file_name.replace('.3mf', '')}/{png_rel}"
        # 如果未能通过 gcode_file 获取到预览，则回退到默认的 plate_1.png
        if not preview_url:
            fallback_preview = get_3mf_preview_image(temp_dir)
            if fallback_preview:
                # fallback_preview 是本地路径，如 temp/<name>/Metadata/plate_1.png
                rel = os.path.relpath(fallback_preview, start=os.path.join('temp'))
                if rel:
                    preview_url = f"/temp/{rel}"
                else:
                    preview_url = None

        # 获取耗材信息
        filament_array, filament_message = get_3mf_filament_info(temp_dir)

        return jsonify({
            'success': True,
            'preview_url': preview_url,
            'filament_array': filament_array,
            'gcode_file': selected_gcode,
            'plate_index': selected_plate,
            'message': f"成功分析文件: {filament_message}"
        })
        
    except Exception as e:
        print(f"\n3mf文件分析请求失败': {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/temp/<path:filename>')
def serve_temp_files(filename):
    """提供临时文件的访问"""
    temp_dir = data_path('temp')
    return send_from_directory(temp_dir, filename)

@app.route('/api/get-filament-mapping')
def get_filament_mapping_api():
    """获取耗材映射API"""
    try:
        ha_config = config_manager.get_ha_config()
        
        if not ha_config['url'] or not ha_config['token'] or not ha_config['printer_entity']:
            return jsonify({'success': False, 'error': 'Home Assistant配置不完整'})
        
        # 自动检测AMS数量
        ams_count = 0
        for ams_index in range(1, 5):  # 最多检测4个AMS
            tray_entity = f"sensor.{ha_config['printer_entity']}_ams_{ams_index}_tray_1"
            headers = {
                "Authorization": f"Bearer {ha_config['token']}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(f"{ha_config['url']}/api/states/{tray_entity}", headers=headers, timeout=5)
            if response.status_code == 200:
                ams_count = ams_index
            else:
                break
        
        filament_mapping, message = get_filament_mapping(
            ha_config['printer_entity'],
            ams_count,
            ha_config['url'],
            ha_config['token']
        )
        
        return jsonify({
            'success': True,
            'filament_mapping': filament_mapping,
            'ams_count': ams_count,
            'message': message
        })
        
    except Exception as e:
        print(f"\n获取耗材映射请求失败: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/upload-progress')
def get_upload_progress():
    """获取上传进度API"""
    try:
        global upload_progress
        upload_id = request.args.get('upload_id')
        
        if upload_id and upload_id in upload_sessions:
            # 如果提供了upload_id并且存在于sessions中，返回会话特定的进度
            session = upload_sessions[upload_id]
            return jsonify({
                'current_file': session.get('current_file', ''),
                'progress': session.get('progress', 0),
                'current_file_index': session.get('current_file_index', 0),
                'total_files': session.get('total_files', 0),
                'status': session.get('status', 'idle'),
                'message': session.get('message', '')
            })
        else:
            # 否则返回全局进度
            return jsonify(upload_progress)
            
    except Exception as e:
        return jsonify({
            'current_file': '',
            'progress': 0,
            'current_file_index': 0,
            'total_files': 0,
            'status': 'error',
            'message': f'获取上传进度失败: {str(e)}'
        })

@app.route('/api/download-progress')
def get_download_progress():
    """获取下载进度API"""
    global download_progress
    return jsonify(download_progress)

@app.route('/api/upload-any', methods=['POST'])
def upload_any_files():
    """上传任意文件到打印机指定路径"""
    try:
        # 检查是否有文件
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': '没有选择文件'})
        
        files = request.files.getlist('files')
        target_path = request.form.get('path', '/')
        upload_id = request.form.get('upload_id', f'upload_{int(time.time())}')
        
        if len(files) == 0:
            return jsonify({'success': False, 'error': '没有选择文件'})
        
        # 过滤掉空文件名
        valid_files = [f for f in files if f.filename]
        if not valid_files:
            return jsonify({'success': False, 'error': '没有有效的文件'})
        
        config = config_manager.get_ftp_config()
        
        # 初始化上传会话
        upload_sessions[upload_id] = {
            'total_files': len(valid_files),
            'current_file_index': 0,
            'current_file': '',
            'progress': 0,
            'status': 'starting',
            'message': f'准备上传 {len(valid_files)} 个文件...'
        }
        
        results = []
        client = None
        
        for index, file in enumerate(valid_files):

            # 检查文件名长度
            if len(file.filename) > 47:
                results.append({
                    'file': file.filename,
                    'success': False,
                    'message': f'文件名超过47个字符限制: {len(file.filename)}个字符'
                })
                continue
            
            try:
                # 为每个文件创建临时文件
                temp_file = tempfile.NamedTemporaryFile(
                    delete=False, 
                    suffix=os.path.splitext(file.filename)[1],
                    prefix=f'tmp_{uuid.uuid4().hex[:8]}_'
                )
                file.save(temp_file.name)
                temp_file.close()
                
                # 更新上传进度
                update_upload_session(
                    upload_id,
                    'uploading',
                    f'正在上传文件 {index + 1}/{len(valid_files)}: {file.filename}',
                    file.filename,
                    index,
                    len(valid_files),
                    (index / len(valid_files)) * 100
                )
                
                # 创建FTP客户端
                client = SimpleFTPSClient(config['host'], config['port'], config['user'], config['password'])
                
                # 准备上传环境
                success, msg = client.prepare_upload_environment(target_path)
                if not success:
                    results.append({
                        'file': file.filename,
                        'success': False,
                        'message': f'无法准备上传环境: {msg}'
                    })
                    continue
                
                # 定义进度回调函数
                def progress_callback(current_file, file_progress, uploaded_bytes, file_size):
                    # 计算总体进度
                    base_progress = (index / len(valid_files)) * 100
                    current_progress = (file_progress / 100) * (100 / len(valid_files))
                    total_progress = base_progress + current_progress
                    
                    update_upload_session(
                        upload_id,
                        'uploading',
                        f'{current_file}: {file_progress:.1f}% ({format_file_size(uploaded_bytes)} / {format_file_size(file_size)})',
                        current_file,
                        index,
                        len(valid_files),
                        total_progress
                    )
                
                # 上传文件
                success, message = client.upload_file(temp_file.name, file.filename, progress_callback=progress_callback)
                client.quit()
                results.append({
                    'file': file.filename,
                    'success': success,
                    'message': '上传成功' if success else f'上传失败: {message}'
                })
                
                # 删除临时文件
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
                    
                # 短暂延迟，避免服务器压力
                time.sleep(1)
                
            except Exception as e:
                results.append({
                    'file': file.filename,
                    'success': False,
                    'message': f'上传错误: {str(e)}'
                })
        
        if client:
            client.quit()
        
        # 检查是否有成功的上传
        success_count = sum(1 for r in results if r['success'])
        fail_count = len(results) - success_count

        # 清理上传会话
        if upload_id in upload_sessions:
            del upload_sessions[upload_id]
        
        if fail_count > 0:
            return jsonify({
                'success': True,
                'message': f'上传完成! 成功: {success_count}, 失败: {fail_count}',
                'results': results
            })
        else:
            return jsonify({
                'success': True,
                'message': f'成功上传 {success_count} 个文件',
                'results': results
            })
        
    except Exception as e:
        if 'upload_id' in locals() and upload_id in upload_sessions:
            del upload_sessions[upload_id]
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/create-automation', methods=['POST'])
def create_automation():
    """创建自动化API"""
    global upload_progress
    
    try:
        data = request.json
        print_queue = data.get('print_queue', [])
        ftp_config = config_manager.get_ftp_config()
        ha_config = config_manager.get_ha_config()
        upload_path = data.get('upload_path', ftp_config['path'])
        skip_server_files = data.get('skip_server_files', False)
        
        if not ha_config['url'] or not ha_config['token']:
            return jsonify({'success': False, 'error': 'Home Assistant配置不完整'})
        
        # 验证所有文件的耗材配置
        for i, file_config in enumerate(print_queue):
            filament_array = file_config.get('filament_array', [])
            ams_mapping = file_config.get('ams_mapping', [])
            
            for j, filament in enumerate(filament_array):
                if filament != -1 and ams_mapping[j] == -1:
                    return jsonify({
                        'success': False, 
                        'error': f'文件 {file_config.get("filename")} 中的耗材位置 {j} 未分配实际耗材'
                    })
        
        # 获取设备ID
        device_id, device_message = get_device_id(ha_config['printer_entity'], ha_config['url'], ha_config['token'])
        if not device_id:
            return jsonify({'success': False, 'error': f'无法获取设备ID: {device_message}'})
        
        # 生成webhook ID
        webhook_id = generate_webhook_id()

        # 生成自动化YAML
        automation_yaml = generate_automation_yaml(print_queue, webhook_id, ha_config['printer_entity'], device_id)
        
        # 上传文件到打印机 - 每个文件都新建连接
        uploaded_files = set()

        # 初始化上传进度
        # 优先使用前端传入的 files_to_upload（已去重）；如果没有提供，则从 print_queue 构建
        files_to_upload = []
        requested_files = data.get('files_to_upload')
        if requested_files and isinstance(requested_files, list):
            # 过滤并验证前端传来的上传列表
            for item in requested_files:
                fp = item.get('file_path') or item.get('filePath') or item.get('path')
                fn = item.get('filename') if item.get('filename') else (os.path.basename(fp) if fp else None)
                if not fp:
                    continue
                if os.path.exists(fp) and fp not in uploaded_files:
                    files_to_upload.append({'file_path': fp, 'filename': fn})
                    uploaded_files.add(fp)
        else:
            for file_config in print_queue:
                # 检查是否需要跳过服务器文件
                if skip_server_files and file_config.get('is_server_file', False) and file_config.get('downloaded', False):
                    print(f"跳过服务器文件上传: {file_config.get('filename')}")
                    continue

                file_path = file_config.get('file_path')
                if file_path and file_path not in uploaded_files and os.path.exists(file_path):
                    files_to_upload.append({
                        'file_path': file_path,
                        'filename': file_config.get('filename')
                    })
        
        total_files = len(files_to_upload)
        update_upload_progress(None, 0, 0, total_files, 'starting', '准备开始上传文件...')
        
        for index, file_info in enumerate(files_to_upload):
            file_path = file_info['file_path']
            filename = file_info['filename']
            
            # 为每个文件创建新的FTP客户端实例
            client = SimpleFTPSClient(ftp_config['host'], ftp_config['port'], ftp_config['user'], ftp_config['password'])
            
            print(f"开始上传文件: {filename} 到路径: {upload_path}")
            update_upload_progress(filename, 0, index, total_files, 'uploading', f'开始上传文件 {filename}')
            
            # 定义进度回调函数
            def progress_callback(current_file, progress, uploaded_bytes, file_size):
                update_upload_progress(
                    current_file, 
                    progress, 
                    index, 
                    total_files, 
                    'uploading',
                    f'{current_file}: {progress:.1f}% ({format_file_size(uploaded_bytes)} / {format_file_size(file_size)})'
                )
            
            # 上传文件
            success, message = client.upload_file(file_path, filename, upload_path, progress_callback=progress_callback)
            
            # 立即关闭连接
            client.quit()
            
            if not success:
                update_upload_progress(filename, 0, index, total_files, 'error', f'文件 {filename} 上传失败: {message}')
                return jsonify({'success': False, 'error': f'文件 {filename} 上传失败: {message}'})
            
            uploaded_files.add(file_path)
            update_upload_progress(filename, 100, index + 1, total_files, 'uploading', f'文件 {filename} 上传成功')
            
            # 文件间延迟，避免服务器压力
            time.sleep(4)

        print(f"全部上传完成，共上传 {len(uploaded_files)} 个文件到路径: {upload_path}")
        update_upload_progress(None, 100, total_files, total_files, 'completed', '所有文件上传完成，正在创建自动化...')

        # 在Home Assistant中创建自动化
        automation_created = create_automation_in_ha(automation_yaml, ha_config['url'], ha_config['token'])
        
        if not automation_created:
            update_upload_progress(None, 100, total_files, total_files, 'error', '文件上传成功，但创建自动化失败')
            return jsonify({
                'success': False,
                'automation_yaml': automation_yaml,
                'error': '文件上传成功，但在Home Assistant中创建自动化失败'
            })
        
        print(f"自动化创建成功，Webhook ID: {webhook_id}")
        update_upload_progress(None, 100, total_files, total_files, 'success', '自动化创建成功')
        
        return jsonify({
            'success': True,
            'webhook_id': webhook_id,
            'automation_yaml': automation_yaml,
            'message': '自动化创建成功，文件已上传到打印机'
        })
        
    except Exception as e:
        print(f"\n创建自动化请求失败: {str(e)}")
        update_upload_progress(None, 0, 0, 0, 'error', f'创建自动化失败: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/start-print', methods=['POST'])
def start_print():
    """开始打印API"""
    try:
        data = request.json
        webhook_id = data.get('webhook_id')
        
        ha_config = config_manager.get_ha_config()
        
        if not ha_config['url']:
            return jsonify({'success': False, 'error': 'Home Assistant URL未配置'})
        
        # 调用webhook（规范化 URL，去掉尾部可能的斜杠）
        base = normalize_base_url(ha_config['url'])
        webhook_url = f"{base}/api/webhook/{webhook_id}"
        response = requests.post(webhook_url, timeout=30)
        
        if response.status_code in [200, 201, 202]:
            # 清空temp文件夹
            try:
                temp_dir = data_path('temp')
                if os.path.exists(temp_dir):
                    # 删除temp文件夹及其所有内容
                    shutil.rmtree(temp_dir)
                    # 重新创建空的temp文件夹
                    os.makedirs(temp_dir)
                    print(f"已清空temp文件夹")
                else:
                    os.makedirs(temp_dir)
            except Exception as cleanup_error:
                print(f"清空temp文件夹时出错: {cleanup_error}")
            return jsonify({'success': True, 'message': '打印任务已开始'})
        else:
            return jsonify({'success': False, 'error': f'调用webhook失败: {response.status_code}'})
            
    except Exception as e:
        print(f"\n开始打印请求失败: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    # 计算端口：环境变量优先 -> config.ini -> 默认5000
    port_env = os.environ.get('PORT') or os.environ.get('BROWSER_PORT')
    host_env = os.environ.get('BIND_HOST') or os.environ.get('HOST') or '0.0.0.0'
    try:
        port = int(port_env) if port_env else 5000
    except Exception:
        port = 5000
    
    # 仅在非容器环境下尝试打开浏览器
    if not is_running_in_docker():
        print("检测到非容器环境，尝试自动打开浏览器")
        browser_host = '127.0.0.1' if host_env in ['0.0.0.0', '::'] else host_env
        threading.Thread(target=open_browser, args=(port, browser_host), daemon=True).start()
    else:
        print("检测到容器环境，跳过自动打开浏览器")

    # 启动Flask应用
    print(f"启动服务...")
    print(f"浏览器访问: http://{host_env}:{port}")
    app.run(debug=False, host=host_env, port=port)