"""
获取当前网络下的所有设备ip和mac
获取当前设备下所有有程序的端口
向所有程序所在端口发起http-post请求其 /__gnip__ 发送所有设备信息
"""
import requests
import gnip
import random
from file import *


class Ping:  # 通过多线程高速ping输入地址判断该地址是否有设备
    def __init__(self, ip_data: list, workflow_count: int, timeout: float):
        self.ip_data = ip_data
        self.ip_data2 = ip_data
        self.result = {}
        self.lock = threading.Lock()
        self.lock2 = threading.Lock()
        self.timeout = timeout
        self.PingManager = PingManager()
        threading.Thread(target=self.get_mac).start()

        for _ in range(workflow_count):
            threading.Thread(target=self.ping).start()

    def ping(self):  # ping
        while True:
            try:
                with self.lock:
                    while not self.ip_data:  # 阻塞至有参数
                        pass

                    ip = self.ip_data.pop(0)

                ping = self.PingManager.ping(ip, timeout=self.timeout)
                if ping and (ip not in self.result):
                    self.result[ip] = 'N/A'
                elif (not ping) and (ip in self.result):
                    del self.result[ip]
            except Exception:
                pass
            self.ip_data.append(ip)

            if self.result:
                try:
                    ip = list(self.result.keys()).pop(random.randint(0, len(list(self.result.keys()))-1))

                    ping = self.PingManager.ping(ip, timeout=self.timeout)
                    if (not ping) and (ip in self.result):
                        del self.result[ip]
                except Exception:
                    pass

    def get_mac(self):
        while True:
            for ip in self.result.copy():
                try:
                    mac = get_mac_address(ip)
                    if mac:
                        self.result[ip] = mac
                except Exception:
                    pass
            time.sleep(1)


class LinkingUtility:
    def __init__(self):
        self.program = []
        self.device_list = []
        threading.Thread(target=self.connect).start()
        threading.Thread(target=self.get_device_list).start()
        threading.Thread(target=self.send_to_program).start()

    def connect(self):  # 获取所有需要提供的程序列表
        while True:
            ports = get_listening_ports()  # 获取所有程序的端口
            for item in ports:
                if 'http://127.0.0.1:' + str(item['port']) + '/__gnip__' in self.program:
                    continue

                try:
                    if requests.post('http://127.0.0.1:' + str(item['port']) + '/__gnip__', json={'type': False}, timeout=0.5).json()['message'] == 200:
                        self.program.append('http://127.0.0.1:' + str(item['port']) + '/__gnip__')
                except Exception:
                    pass
            time.sleep(0.5)

    def get_device_list(self):
        p = Ping([], 128, 10)# 获取所有设备
        while True:
            try:
                network_data = list(get_network_interfaces())  # 获取本机ip与子网掩码

                if network_data[0] == '127.0.0.1':
                    continue

                # 修改子网掩码前两位为 255 避免相邻ip计算过久
                network_data[1] = network_data[1].split('.')
                network_data[1][0] = '255'
                network_data[1][1] = '255'
                network_data[1] = '.'.join(network_data[1])

                ip_data = gnip.gnip(network_data[0], network_data[1])  # 获取所有相邻ip

                for ip in ip_data[0: min(512, len(ip_data)-1)]:
                    if ip not in p.ip_data2:
                        p.ip_data2 = ip_data.copy()
                        p.ip_data = ip_data[0: min(512, len(ip_data)-1)]
                        break

                for ip in p.ip_data2:
                    if ip not in ip_data:
                        p.ip_data2 = ip_data.copy()
                        p.ip_data = ip_data[0: min(512, len(ip_data)-1)]
                        break

                self.device_list = p.result
            except Exception:
                pass

    def send_to_program(self):  # 向程序发送设备列表
        while True:
            for url in self.program:
                try:
                    if requests.post(url, json={'type': True, 'device_list': [(item, self.device_list[item]) for item in self.device_list]}, timeout=0.5).json()['message'] != 200:
                        del self.program[self.program.index(url)]
                except Exception:
                    del self.program[self.program.index(url)]
            time.sleep(1)


def main():
    LinkingUtility()


if __name__ == '__main__':
    main()