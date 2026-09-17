# -*- coding: utf-8 -*-
"""
外网IP自动上报工具（reporter）
====================================
功能：
  1. 每60秒检测本机外网IP是否变化
  2. 变化（或首次运行）时，用 Fernet 加密 {ip, timestamp} 后
     POST 到 ERP 服务端 /api/user/report_ip/，服务端自动写入 data_iplist
  3. 支持开机自启：可配合 "启动文件夹" 的快捷方式或 schtasks 使用

配置（同目录 config.json，首次运行自动生成模板）：
{
  "server_url": "http://127.0.0.1:8000",     // ERP后端地址
  "interval": 60,                            // 检测间隔（秒）
  "fernet_key": "JbpvfXHDkCOY7g8jGdKwmX4FqZs5Tz3PvN1hA6yB9cE="  // 与服务端一致
}

用法：
  reporter.exe                    读取同目录 config.json
  reporter.exe --once             只上报一次就退出（测试用）
"""

import json
import time
import sys
import os
import logging
from datetime import datetime

import requests
from cryptography.fernet import Fernet

import socket

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
LOG_PATH = os.path.join(BASE_DIR, 'reporter.log')

# --noconsole 打包后 sys.stdout 为 None，StreamHandler 会崩溃，需防御
_handlers = [logging.FileHandler(LOG_PATH, encoding='utf-8')]
if sys.stdout is not None:
    _handlers.append(logging.StreamHandler(sys.stdout))
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=_handlers,
)
log = logging.getLogger('reporter')

DEFAULT_CONFIG = {
    'server_url': 'http://127.0.0.1:8000',
    'interval': 60,
    'fernet_key': 'JbpvfXHDkCOY7g8jGdKwmX4FqZs5Tz3PvN1hA6yB9cE=',
}

# 公网IP探测服务（依次尝试，任一成功即用）
IP_APIS = [
    ('https://api.ipify.org', 'text'),
    ('https://ifconfig.me/ip', 'text'),
    ('https://myexternalip.com/raw', 'text'),
    ('https://icanhazip.com', 'text'),
]


def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
        log.info('已生成默认配置文件: %s，请按需修改后重新运行', CONFIG_PATH)
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def get_public_ip():
    """获取本机外网IP，任一探测服务成功即返回"""
    for url, mode in IP_APIS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                ip = r.text.strip()
                if ip and len(ip) <= 45 and ('.' in ip or ':' in ip):
                    return ip
        except Exception:
            continue
    return None


def report(cfg, ip):
    """Fernet 加密上报 IP 到服务端"""
    f = Fernet(cfg['fernet_key'].encode())
    payload = json.dumps({'ip': ip, 'timestamp': int(time.time())})
    encrypted = f.encrypt(payload.encode()).decode()
    url = cfg['server_url'].rstrip('/') + '/api/user/report_ip/'
    try:
        r = requests.post(url, json={'data': encrypted}, timeout=15)
        if r.status_code == 200:
            data = r.json()
            log.info('上报成功 ip=%s created=%s', data.get('ip'), data.get('created'))
            return True
        log.warning('上报失败 HTTP %s: %s', r.status_code, r.text[:200])
    except Exception as e:
        log.warning('上报异常: %s', e)
    return False


def heartbeat(cfg, ip):
    """向服务端发送心跳（加密），主程序据此判断 reporter 是否在运行"""
    f = Fernet(cfg['fernet_key'].encode())
    payload = json.dumps({
        'ip': ip,
        'host': socket.gethostname(),
        'timestamp': int(time.time()),
    })
    encrypted = f.encrypt(payload.encode()).decode()
    url = cfg['server_url'].rstrip('/') + '/api/user/reporter_heartbeat/'
    try:
        r = requests.post(url, json={'data': encrypted}, timeout=15)
        if r.status_code == 200:
            return True
        log.warning('心跳失败 HTTP %s: %s', r.status_code, r.text[:200])
    except Exception as e:
        log.warning('心跳异常: %s', e)
    return False


def main():
    cfg = load_config()
    log.info('reporter 启动 server=%s interval=%ss', cfg['server_url'], cfg['interval'])

    last_ip = None
    once = '--once' in sys.argv

    while True:
        ip = get_public_ip()
        if not ip:
            log.warning('未能获取外网IP，%s秒后重试', cfg['interval'])
        else:
            if ip != last_ip:
                log.info('检测到IP: %s（上次: %s），上报中...', ip, last_ip or '无')
                if report(cfg, ip):
                    last_ip = ip
            # 心跳：让服务端知道 reporter 在正常运行
            heartbeat(cfg, ip)

        if once:
            break
        time.sleep(cfg['interval'])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log.info('已停止')
