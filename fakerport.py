#!/usr/bin/env python3

##Written by kelseykm

"""Creates a tcp server that does the three-way handshake, sends a fake banner and then closes connection"""

import threading
import socket
from random import choice

HOST = ''
PORT = 19999
ADDR = (HOST, PORT)
BANNERS = ['Apache/2.4.29 (Ubuntu)', 'nginx/1.14.0 (Ubuntu)', 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3', 'Microsoft-IIS/4.3', 'Laravel/8.11.2', 'SSH-2.0-OpenSSH_7.4', 'Microsoft-IIS/8.1', 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2', 'Apache/2.4.6 (CentOS) ', 'OpenSSL/1.0.2k-fips ', 'PHP/5.4.16', 'nginx/1.8.1', 'MDaemon Webmail/17.5.1', 'Microsoft ESMTP MAIL Service/14.1.218.15', 'wildix-http-server', 'lighttpd/1.4.35 atos/6.4.3.1 (server0)', 'Apache/2.4.33 (Win32) ', 'OpenSSL/1.1.0h ', 'PHP/7.2.5', 'Microsoft-IIS/7.5', '220-QTCP (FTP)', 'SSH-2.0-Zyxel SSH server', 'GoAhead-Webserver/3.6.5', 'SSH-2.0-1yj6goHqD_6q', 'Microsoft-IIS/6.7', 'Boa/0.94.14rc21', 'Apache/2.4.18 (Ubuntu)', 'phpMyFAQ/2.9.13', 'OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)', 'Apache httpd (PHP 7.1.24)', 'nginx/1.10.3 (Ubuntu)', '4.3.5-9.6.24-MariaDB-2&D0c&0', 'postgresql/9.4-3', 'ESMTP Exim 4.93 #2', 'Microsoft-IIS/6.9']

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.listen()

def handle_conn(conn,addr):
    conn.send(choice(BANNERS).encode())
    conn.close()
    raise SystemExit

def receive_conn():
    try:
        while True:
            connection, address = server.accept()
            threading.Thread(target=handle_conn, args=(connection,address)).start()
    except:
        raise SystemExit

if __name__ == '__main__':
    receive_conn()
