import psutil
import re
import netifaces
import subprocess
import platform
import socket
import struct
import select
import time
import threading


def get_local_ip():
    try:
        # 创建一个连接到外部服务器的socket（并不实际连接）
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 连接到一个公共服务器（不一定要可达，只是为了获取本地出口IP）
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception:
        return "127.0.0.1"  # 默认返回本地回环地址


class PingManager:
    def __init__(self):
        """
        初始化Ping管理器

        参数:
            max_sockets: 最大套接字数量，避免创建过多套接字消耗资源
        """
        self.socket_pool = []
        self.id = 0
        self.id_pool = []
        self.pid = 12345  # 固定标识符，也可以使用进程ID
        self.payload = b'abcdefghijklmnopqrstuvwxyz'  # 固定payload
        self.lock = threading.Lock()

    def _create_socket(self):
        """创建新的ICMP套接字"""
        # 创建原始ICMP套接字
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP
        )
        # 设置套接字超时
        sock.settimeout(2)
        return sock

    def _get_free_socket(self):
        """从池中获取空闲套接字，没有则创建新的"""
        with self.lock:
            if self.id == 65535:
                self.id = 0
            else:
                self.id += 1

            while self.id in self.id_pool:
                time.sleep(0.1)

            self.id_pool.append(self.id)
            if self.socket_pool:
                return self.socket_pool.pop(0), self.id
            else:
                sock = self._create_socket()
                return sock, self.id


    def _release_socket(self, sock, id_):
        """重置并释放套接字到池"""
        t = time.time()

        self.id_pool.remove(id_)

        # 1. 清除接收缓冲区中的残留数据
        try:
            # 设置非阻塞模式以便立即读取
            sock.setblocking(False)
            # 读取所有可用数据
            while True:
                try:
                    sock.recv(1024)
                except BlockingIOError:
                    break  # 没有更多数据
        except Exception:
            # 如果出错则关闭套接字，不再放回池
            sock.close()
            return

        # 2. 恢复阻塞模式和超时设置
        try:
            sock.setblocking(True)
            sock.settimeout(2)  # 重置超时
        except Exception:
            sock.close()
            return

        self.socket_pool.append(sock)

    def _calculate_checksum(self, data):
        """计算校验和"""
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum

    def ping(self, host, timeout=5):
        """
        执行ping操作z

        参数:
            host: 目标主机
            timeout: 超时时间（秒）

        返回:
            成功返回True，失败返回False
        """
        sock, seq = self._get_free_socket()
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # 解析主机名到IP
                ip = socket.gethostbyname(host)

                # 构造ICMP包
                header = struct.pack('!BBHHH', 8, 0, 0, self.pid, seq)
                checksum = self._calculate_checksum(header + self.payload)
                header = struct.pack('!BBHHH', 8, 0, checksum, self.pid, seq)
                packet = header + self.payload

                # 发送请求
                sock.sendto(packet, (ip, 0))

                # 等待响应
                ready = select.select([sock], [], [], max(timeout - (time.time() - start_time), 0.1))
                if ready[0]:
                    recv_packet, addr = sock.recvfrom(1024)
                    if addr[0] == ip:
                        # 解析ICMP响应
                        icmp_header = recv_packet[20:28]
                        icmp_type, _, _, resp_pid, resp_seq = struct.unpack('!BBHHH', icmp_header)
                        if icmp_type == 0 and resp_pid == self.pid:
                            self._release_socket(sock, seq)
                            return True

            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass

                sock = self._create_socket()
                time.sleep(0.1)

        self._release_socket(sock, seq)
        return False


def get_network_interfaces():
    """获取所有网络接口的信息，包括IP地址和子网掩码"""
    local_ip = get_local_ip()

    # 获取所有网络接口名称
    for interface in netifaces.interfaces():
        # 获取接口的详细信息
        addrs = netifaces.ifaddresses(interface)

        # 检查是否有IPv4地址信息
        if netifaces.AF_INET in addrs:
            ipv4_info = addrs[netifaces.AF_INET][0]
            ip_address = ipv4_info.get('addr')
            netmask = ipv4_info.get('netmask')

            if ip_address and netmask and ip_address == local_ip:
                return ip_address, netmask

    return local_ip, None


def get_mac_address(ip):
    """
    根据IP地址获取对应的MAC地址

    参数:
        ip (str): 目标IP地址

    返回:
        str: MAC地址字符串，格式如"aa:bb:cc:dd:ee:ff"；获取失败则返回None
    """
    os_type = platform.system().lower()
    mac_address = None

    try:
        if os_type == "windows":
            # Windows系统执行arp命令
            output = subprocess.check_output(
                ["arp", "-a", ip],
                shell=True,
                stderr=subprocess.STDOUT,
                text=True
            )
            # 正则表达式匹配MAC地址
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
            if match:
                mac_address = match.group(0).replace("-", ":").lower()

        elif os_type in ["linux", "darwin"]:
            # Linux和macOS系统执行arp命令
            output = subprocess.check_output(
                ["arp", ip],
                stderr=subprocess.STDOUT,
                text=True
            )
            # 正则表达式匹配MAC地址
            match = re.search(r"([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})", output)
            if match:
                mac_address = match.group(0).lower()

        else:
            return None

    except subprocess.CalledProcessError:
        pass
    except Exception:
        pass

    return mac_address


def get_listening_ports():
    """获取所有处于监听状态的端口及其相关信息"""
    listening_ports = []

    # 遍历所有网络连接
    for conn in psutil.net_connections(kind='inet'):
        # 筛选出处于监听状态的连接
        if conn.status == psutil.CONN_LISTEN:
            # 获取进程信息
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                process_path = process.exe() if hasattr(process, 'exe') else "N/A"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = "Unknown"
                process_path = "N/A"

            # 收集信息
            listening_ports.append({
                'port': conn.laddr.port,
                'ip': conn.laddr.ip,
                'pid': conn.pid,
                'process_name': process_name,
                'process_path': process_path
            })

    # 按端口号排序
    listening_ports.sort(key=lambda x: x['port'])
    return listening_ports

