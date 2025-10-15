"""
get_neighbor_ips
gnip.gnip(ip, subnet_mask)

用于获取所有相邻ip
"""

import socket
import struct


def ip_to_int(ip):
    """将IP地址转换为整数以便计算，支持IPv4和IPv6"""
    try:
        # 尝试IPv4解析
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        # 尝试IPv6解析
        # 将128位地址拆分为两个64位整数
        packed = socket.inet_pton(socket.AF_INET6, ip)
        high, low = struct.unpack(">QQ", packed)
        return (high << 64) | low


def int_to_ip(ip_int, ip_version=None):
    """将整数转换回IP地址格式，支持IPv4和IPv6"""
    if ip_version == 4 or (ip_version is None and ip_int <= 0xFFFFFFFF):
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    else:
        # 处理IPv6
        high = (ip_int >> 64) & 0xFFFFFFFFFFFFFFFF
        low = ip_int & 0xFFFFFFFFFFFFFFFF
        packed = struct.pack(">QQ", high, low)
        return socket.inet_ntop(socket.AF_INET6, packed)


def get_ip_version(ip):
    """判断IP地址版本"""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return 6
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return 4
        except OSError:
            raise ValueError(f"无效的IP地址: {ip}")


def gnip(ip, subnet_mask):
    """
    get_neighbor_ips

    计算同一子网内所有可访问的IP地址（排除输入IP），并按数字距离排序
    支持IPv4和IPv6

    参数:
        ip: 输入的IP地址字符串（如"192.168.1.100"或"2001:db8::1"）
        subnet_mask: 子网掩码字符串（如"255.255.255.0"或"ffff:ffff:ffff:ffff::"）

    返回:
        排序后的IP地址列表，按与输入IP的数字距离从小到大排序
    """
    ip_version = get_ip_version(ip)

    # 将IP和子网掩码转换为整数
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(subnet_mask)

    # 计算网络地址和广播地址
    network_int = ip_int & mask_int

    # 根据IP版本计算广播地址
    if ip_version == 4:
        max_int = 0xFFFFFFFF  # IPv4是32位
    else:
        max_int = (1 << 128) - 1  # IPv6是128位

    broadcast_int = network_int | (~mask_int & max_int)

    # 计算子网内的第一个和最后一个可用IP
    first_ip_int = network_int + 1
    last_ip_int = broadcast_int - 1

    # 如果子网内只有一个IP，则没有其他可访问IP
    if first_ip_int > last_ip_int:
        return []

    # 生成子网内所有IP，排除输入IP
    neighbor_ips = []
    # 对于IPv6，大子网可能包含太多地址，这里添加一个安全检查
    if ip_version == 6 and (last_ip_int - first_ip_int) > 1000000:
        raise ValueError("IPv6子网过大，可能包含超过100万个地址，不适合计算所有邻居")

    for current_int in range(first_ip_int, last_ip_int + 1):
        if current_int != ip_int:
            # 计算与输入IP的数字距离
            distance = abs(current_int - ip_int)
            neighbor_ips.append((int_to_ip(current_int, ip_version), distance))

    # 按距离排序，然后提取IP地址
    neighbor_ips.sort(key=lambda x: x[1])
    return [ip for ip, _ in neighbor_ips]
