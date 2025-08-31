#!/usr/bin/env python3
"""
从两个 GoBGP gRPC 实例监听 EVPN Type-2 路由变化，并根据线程策略操作 neigh 和 fdb 表。
"""
import sys
import logging
import threading
import time
import subprocess
from typing import Dict, Optional, Tuple

import grpc
from pyroute2 import IPRoute

# 假设你已经通过 protoc 生成了 GoBGP 的 Python gRPC 客户端
# 下载或复制 GoBGP 的 proto 文件: https://github.com/osrg/gobgp/tree/master/api
import gobgp_pb2
import gobgp_pb2_grpc
import attribute_pb2

# 配置
LOG_LEVEL = logging.INFO
BRIDGE_IFNAME = 'br-vxlan'  # 本地桥接接口名称
VXLAN_PORT_NAME = 'vxlan0'  # VTEP端口名称

ASN1 = 65001                # GoBGP 实例的 AS 号
ROUTER_ID1 = '192.168.1.65' # 本机 Router ID (用于 RD, GW-IP, Next-Hop)
ASN2 = 65002                # GoBGP 实例的 AS 号
ROUTER_ID2 = '192.168.2.65' # 本机 Router ID (用于 RD, GW-IP, Next-Hop)
VNI = 100                   # VNI (用于 RD, RT, Label)

# gRPC 端点
GRPC_ENDPOINTS = [
    {'host': '127.0.0.1', 'port': 50051, 'name': 'grpc1'},
    {'host': '127.0.0.1', 'port': 50052, 'name': 'grpc2'}
]

# 初始化日志
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s [%(threadName)s] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# 全局 IPRoute 实例 (线程安全，但操作需注意)
ip = IPRoute()

# 桥接接口索引缓存
bridge_index = None

vxlan_port_index = None

# key: "{vni}-{ip}"
# value: [{"ip": "", "mac": "", "nexthop": "", "vni": "", "rd": ""}]
REACHABLE_ROUTES = {}

def get_route_key(type2route: dict) -> str:
    return "%s-%s" % (type2route['vni'], type2route['ip'])

def sort_routes(routes: [dict]) -> None:
    def sort_key(route: dict):
        return (route['nexthop'], )
    return routes.sort(key=sort_key)

def get_bridge_index() -> int:
    """获取桥接接口的 ifindex (全局唯一)"""
    global bridge_index
    if bridge_index is None:
        links = ip.get_links(ifname=BRIDGE_IFNAME)
        if not links:
            raise RuntimeError(f"Bridge interface '{BRIDGE_IFNAME}' not found.")
        bridge_index = links[0]['index']
        logger.info(f"Bridge '{BRIDGE_IFNAME}' index: {bridge_index}")
    return bridge_index

def get_vxlan_port_index() -> int:
    """获取桥接接口的 ifindex (全局唯一)"""
    global vxlan_port_index
    if vxlan_port_index is None:
        links = ip.get_links(ifname=VXLAN_PORT_NAME)
        if not links:
            raise RuntimeError(f"VTEP interface '{VXLAN_PORT_NAME}' not found.")
        vxlan_port_index = links[0]['index']
        logger.info(f"VTEP interface '{VXLAN_PORT_NAME}' index: {vxlan_port_index}")
    return vxlan_port_index

def get_bridge_ip_and_mac(ifname: str) -> Optional[Tuple[str, str]]:
    """
    获取指定桥接接口的主 IP 地址和 MAC 地址。

    Args:
        ifname (str): 网络接口名称。

    Returns:
        Optional[Tuple[str, str]]: (IP地址, MAC地址) 的元组，如果未找到则返回 None。
    """
    ipr = IPRoute()
    try:
        # 获取接口信息
        links = ipr.get_links(ifname=ifname)
        if not links:
            logger.error(f"Interface '{ifname}' not found.")
            return None

        # 提取 MAC 地址
        mac_addr = links[0].get_attr('IFLA_ADDRESS')
        if not mac_addr:
            logger.error(f"MAC address not found for interface '{ifname}'.")
            return None

        # 获取 IP 地址 (只取主 IP，IPv4)
        addrs = ipr.get_addr(ifname=ifname, family=2)  # AF_INET = 2
        ipv4_addr = None
        for addr in addrs:
            # 检查是否为主地址 (IFA_FLAGS 0 或没有 IFA_F_SECONDARY)
            if 'IFA_FLAGS' not in addr or addr['IFA_FLAGS'] == 0:
                prefix_len = addr['prefixlen']
                ip_with_prefix = f"{addr.get_attr('IFA_ADDRESS')}/{prefix_len}"
                # 只取 IP 部分用于宣告
                ipv4_addr = addr.get_attr('IFA_ADDRESS')
                logger.info(f"Found primary IPv4 address on {ifname}: {ip_with_prefix}")
                break

        if not ipv4_addr:
            logger.warning(f"No primary IPv4 address found on interface '{ifname}'.")
            # 即使没有 IP，我们仍然可以宣告 MAC-only 路由
            # return (None, mac_addr) # 如果需要宣告 MAC-only，可以返回这个
            # TODO: change this
            if ROUTER_ID1 == '192.168.1.65':
                ipv4_addr = '192.168.0.65'
            elif ROUTER_ID1 == '192.168.1.87':
                ipv4_addr = '192.168.0.87'
            else:
                return None

        logger.info(f"Interface '{ifname}' - MAC: {mac_addr}, Primary IP: {ipv4_addr}")
        return (ipv4_addr, mac_addr)

    except Exception as e:
        logger.error(f"Error getting info for interface '{ifname}': {e}")
        return None
    finally:
        ipr.close()

def parse_rd(rd_any) -> Optional[str]:
    """
    解析 EVPN MAC/IP 路由中的 RD (Route Distinguisher)。

    Args:
        rd_any (google.protobuf.any_pb2.Any): EVPNMACIPAdvertisementRoute.rd 字段。

    Returns:
        str: 格式化的 RD 字符串 (如 "65001:100", "192.168.1.1:200") 或错误信息。
    """
    # 定义可能的 RD 类型 URL 和对应的消息类
    RD_TYPES = {
        "type.googleapis.com/apipb.RouteDistinguisherTwoOctetASN": attribute_pb2.RouteDistinguisherTwoOctetASN,
        "type.googleapis.com/apipb.RouteDistinguisherIPAddress": attribute_pb2.RouteDistinguisherIPAddress,
        "type.googleapis.com/apipb.RouteDistinguisherFourOctetASN": attribute_pb2.RouteDistinguisherFourOctetASN,
    }

    # 检查 type_url
    type_url = rd_any.type_url
    if type_url not in RD_TYPES:
        loggger.error(f"parse_rd: unknown RD type: {type_url}")
        return None

    # 获取对应的消息类
    rd_message_class = RD_TYPES[type_url]
    # 创建该类型的消息实例
    rd_message = rd_message_class()
    try:
        # 尝试解包
        rd_any.Unpack(rd_message)
    except Exception as e:
        logger.error(f"pasrse_rd: failed to unpack RD: {e}")
        return None

    # 根据解包后的消息类型和字段构建 RD 字符串
    try:
        if type_url == "type.googleapis.com/apipb.RouteDistinguisherTwoOctetASN":
            # 格式: <admin>:<assigned> (admin 通常是 2 字节 ASN)
            return f"{rd_message.admin}:{rd_message.assigned}"
        elif type_url == "type.googleapis.com/apipb.RouteDistinguisherIPAddress":
            # 格式: <admin_ip>:<assigned>
            return f"{rd_message.admin}:{rd_message.assigned}"
        elif type_url == "type.googleapis.com/apipb.RouteDistinguisherFourOctetASN":
            # 格式: <admin>:<assigned> (admin 通常是 4 字节 ASN)
            return f"{rd_message.admin}:{rd_message.assigned}"
        else:
            # 这个 else 理论上不会执行，因为上面已经检查了 type_url
            logger.error(f"parse_rd: Unexpected RD type after unpack: {type_url}")
            return None
    except AttributeError as e:
        logger.error(f"parse_rd: Missing field in RD message: {e}")
        return None

def parse_type2_nlri(nlri) -> Optional[Dict[str, str]]:
    """解析 EVPN Type-2 NLRI，提取 MAC/IP 信息。"""
    try:
        # 检查是否是 EVPN 路由
        if nlri.type_url != "type.googleapis.com/apipb.EVPNMACIPAdvertisementRoute":
            print(f"Unexpected NLRI type: {nlri_any.type_url}")
            return None

        mac_ip_adv = attribute_pb2.EVPNMACIPAdvertisementRoute()
        try:
            nlri.Unpack(mac_ip_adv)
        except Exception as e:
            print(f"Failed to unpack NLRI: {e}")
            return None

        mac = mac_ip_adv.mac_address
        ip_addr = mac_ip_adv.ip_address 
        rd = parse_rd(mac_ip_adv.rd)
        # 提取 VNI (简化：从标签栈最内层获取，实际可能需解析 RD)
        vni = -1
        if mac_ip_adv.labels and len(mac_ip_adv.labels) > 0:
            # EVPN 标签栈：最内层通常是 VNI
            vni = mac_ip_adv.labels[-1]
        
        return {
            'mac': mac,
            'ip': ip_addr,
            'vni': vni,
            'rd': rd,
        }
    except Exception as e:
        logger.error(f"Error parsing NLRI: {e}")
        return None

def parse_nexthop(pattrs) -> Optional[str]:
    """解析路由属性中的nexthop信息"""
    try:
        for pattr in pattrs:
            if pattr.type_url != "type.googleapis.com/apipb.MpReachNLRIAttribute":
                continue
            mp_reach = attribute_pb2.MpReachNLRIAttribute()
            try:
                pattr.Unpack(mp_reach)
            except Exception as e:
                logger.error(f"Error parsing MpReachNLRIAttribute: {e}")
                continue
            if mp_reach.family.afi == gobgp_pb2.Family.AFI_L2VPN and mp_reach.family.safi == gobgp_pb2.Family.SAFI_EVPN:
                if len(mp_reach.next_hops) == 1:
                    return mp_reach.next_hops[0]
                logger.error(f"what's wrong multiple nexthops: {mp_reach}")
        return None
    except Exception as e:
        logger.error(f"Error when handling pattrs: {e}")
        return None

def handle_route_add_neigh(current_route: dict, available_routes: [dict], is_best_route: bool):
    ip_addr = current_route['ip']
    mac = current_route['mac']
    # --- 关键修改：添加必要的参数 ---
    # 构建 fdb 操作的参数字典
    fdb_params = {
        'lladdr': mac,           # MAC 地址
        'ifindex': get_bridge_index(),    
        'dst': ip_addr,          # 远程 VTEP 的 IP 地址
        'state': 'reachable',
        'nud': 'noarp',
    }

    try:
        # 1. ip add neigh
        ip.neigh('add', **fdb_params)
        logger.info(f"Added neighbor (add): {ip_addr} -> {mac}")
        return
    except Exception as e:
        if "File exists" in str(e):
            # 'add' 时已存在，忽略
            logger.info(f"Neighbor {ip_addr} -> {mac} already exists, try to replace if is_best_route {is_best_route}.")
            if not is_best_route:
                return
            # replace 刷新
            try:
                ip.neigh('replace', **fdb_params)
                logger.info(f"Refreshed neighbor (replace): {ip_addr} -> {mac}")
            except Exception as e2:
                logger.error(f"Failed to replace neighbor {ip_addr} -> {mac}: {e2}")
        else:
            logger.error(f"Failed to add neighbor {ip_addr} -> {mac}: {e}")

def handle_route_add_fdb(current_route: dict, available_routes: list[dict], is_best_route: bool):
    """
    处理添加/更新 FDB 条目。用于 EVPN 场景。

    Args:
        current_route (dict): 当前路由信息，包含 'mac', 'nexthop'(vtep), 'vni'。
        available_routes (list[dict]): 同一 IP 的所有可用路由 (用于 ECMP 等场景，此处主要用于日志)。
        is_best_route (bool): 是否是最佳路由。
    """
    mac = current_route['mac']
    vtep_ip = current_route['nexthop']  # 这是远程 VTEP 的 IP 地址
    vni = current_route['vni']          # 这是 EVPN 实例的 VNI

    # --- 关键修改：添加必要的参数 ---
    # 构建 fdb 操作的参数字典
    fdb_params = {
        'lladdr': mac,           # MAC 地址
        'ifindex': get_vxlan_port_index(),     # VXLAN 设备的索引
        'master': get_bridge_index(),    # 桥接设备的索引 (可选，但推荐)
        'vni': vni,              # VXLAN Network Identifier
        'dst': vtep_ip           # 远程 VTEP 的 IP 地址
    }

    try:
        # 1. 尝试添加 FDB 条目
        # 'add' 操作会失败如果条目已存在 (除非指定 'replace' 或 'update')
        ip.fdb('add', **fdb_params)
        logger.info(f"FDB added: MAC={mac}, VNI={vni}, VTEP={vtep_ip}, on VXLAN-dev({VXLAN_PORT_NAME})")

    except Exception as e:
        error_msg = str(e)
        if "File exists" in error_msg:
            # FDB 条目已存在
            logger.info(f"FDB entry for MAC={mac} already exists.")

            if not is_best_route:
                # 如果当前路由不是最佳路由，我们不关心，直接返回
                logger.info(f"Current route is not best, skipping update for {mac}.")
                return

            # 如果是最佳路由，我们需要更新（刷新）它，可能 VNI 或 VTEP 改变了
            logger.info(f"Best route changed or updated, replacing FDB for {mac}.")

            try:
                # 使用 'replace' 操作
                # 'replace' 会添加新条目或替换已存在的条目
                # 这正是我们想要的：确保 FDB 条目与当前最佳路由完全一致
                ip.fdb('replace', **fdb_params)
                logger.info(f"FDB replaced/refreshed: MAC={mac}, VNI={vni}, VTEP={vtep_ip}")

            except Exception as e2:
                logger.error(f"Failed to replace FDB entry for {mac}: {e2}")

        else:
            # 其他错误，如权限问题、参数无效等
            logger.error(f"Failed to add FDB entry for {mac}: {e}")

def handle_route_del_neigh(current_route: dict, available_routes: [dict], is_best_route: bool):
    if available_routes:
        return handle_route_add_neigh(available_routes[0], available_route, True)
    try:
        ip.neigh('del', lladdr=mac, ifindex=bridge_idx)
        logger.info(f"FDB deleted: {mac}")
    except Exception as e:
        logger.error(f"Failed to delete FDB {mac}: {e}")


def handle_route_del_fdb(current_route: dict, available_routes: [dict], is_best_route: bool):
    if available_routes:
        return handle_route_add_fdb(available_routes[0], available_route, True)
    try:
        ip.fdb('del', lladdr=mac, ifindex=bridge_idx)
        logger.info(f"FDB deleted: {mac}")
    except Exception as e:
        logger.error(f"Failed to delete FDB {mac}: {e}")


def stream_evpn_updates(endpoint: Dict[str, any], thread_strategy: str):
    """流式监听 BGP 更新的通用函数"""
    host = endpoint['host']
    port = endpoint['port']
    name = endpoint['name']

    bridge_idx = get_bridge_index()
    logger.info(f"[{name}] Starting EVPN Type-2 listener for {host}:{port}")

    # 构建 gRPC 通道和存根
    channel = grpc.insecure_channel(f'{host}:{port}')
    stub = gobgp_pb2_grpc.GobgpApiStub(channel)

    try:
        request = gobgp_pb2.ListPathRequest(
            table_type=gobgp_pb2.GLOBAL,
            family=gobgp_pb2.Family(afi=gobgp_pb2.Family.AFI_L2VPN, safi=gobgp_pb2.Family.SAFI_EVPN)
        )
        responses = stub.ListPath(request, metadata=[('better-call', 'gobgp')])

        for response in responses:
            for destination in response.destination.paths:
                nlri_data = parse_type2_nlri(destination.nlri)
                nexthop = parse_nexthop(destination.pattrs)
                if not nlri_data or not nlri_data['mac']:
                    continue
                if nlri_data['vni'] != VNI:
                    continue
                if not nlri_data['rd']:
                    continue
                if not nexthop:
                    continue

                mac = nlri_data['mac']
                ip_addr = nlri_data['ip']
                is_withdraw = destination.is_withdraw
                route_key = get_route_key(nlri_data)
                current_route = {'ip': nlri_data['ip'], 'mac': nlri_data['mac'], 'nexthop': nexthop, 'vni': nlri_data['vni'], 'rd': nlri_data['rd']}
                # 计算 available_routes & is_best_route

                # 这里简化：不区分本地路由，处理所有 Type-2
                if is_withdraw:
                    # 撤销路由：删除 FDB
                    is_best_route = False
                    available_routes = REACHABLE_ROUTES.get(route_key, [])
                    if current_route in available_routes:
                        is_best_route = (current_route == available_routes[0])
                        available_routes.remove(current_route)
                        if not current_route:
                            REACHABLE_ROUTES.pop(route_key)
                    if current_route['rd'].startswith(ROUTER_ID1 + ":") or current_route['rd'].startswith(ROUTER_ID2 + ":"):
                        logger.info(f"ignore self route: {current_route}")
                        continue
                    logger.info(f"withdraw route: current_route={current_route}, available_routes={available_routes}, is_best_route={is_best_route}")
                    handle_route_del_neigh(current_route, available_routes, is_best_route)
                    handle_route_del_fdb(current_route, available_routes, is_best_route)
                else:
                    # 新增路由
                    if route_key not in REACHABLE_ROUTES:
                        available_routes = [current_route]
                        REACHABLE_ROUTES[route_key] = [current_route]
                        is_best_route = True
                    else:
                        available_routes = REACHABLE_ROUTES[route_key]
                        if current_route not in available_routes:
                            available_routes.append(current_route)
                            sort_routes(available_routes)
                        is_best_route = (current_route == available_routes[0])
                    if current_route['rd'].startswith(ROUTER_ID1 + ":") or current_route['rd'].startswith(ROUTER_ID2 + ":"):
                        logger.info(f"ignore self route: {current_route}")
                        continue
                    logger.info(f"announce route: current_route={current_route}, available_routes={available_routes}, is_best_route={is_best_route}")
                    handle_route_add_neigh(current_route, available_routes, is_best_route)
                    handle_route_add_fdb(current_route, available_routes, is_best_route)
    except grpc.RpcError as e:
        logger.error(f"[{name}] gRPC stream error: {e.code()} - {e.details()}")
    except Exception as e:
        logger.error(f"[{name}] Unexpected error in stream: {e}")
    finally:
        channel.close()


def worker_thread(endpoint: Dict[str, any], thread_strategy: str):
    """工作线程入口"""
    while True:
        try:
            stream_evpn_updates(endpoint, thread_strategy)
            logger.warning(f"[{endpoint['name']}] BGP stream ended. Reconnecting in 5 seconds...")
            time.sleep(5)
        except KeyboardInterrupt:
            logger.info(f"[{endpoint['name']}] Shutdown requested.")
            break
        except Exception as e:
            logger.error(f"[{endpoint['name']}] Connection failed: {e}. Reconnecting in 5 seconds...")
            time.sleep(5)

def announce_evpn_route(ip_addr: str, mac_addr: str, asn : int, vni: int, nexthop: str, api_port: int):
    """
    使用 gobgp 命令行工具宣告 EVPN Type-2 路由。

    Args:
        ip_addr (str): 要宣告的 IP 地址。
        mac_addr (str): 要宣告的 MAC 地址。
    """
    router_id = nexthop
    # 构建 gobgp 命令
    # 注意: 命令中的 -t 和 -a 参数位置可能因 gobgp 版本而异，这里按常见用法
    cmd = [
        'gobgp', '-p', str(api_port), 'global',
        '-a', 'evpn',               # 具体地址族
        'rib', 'add', 'macadv',
        mac_addr,                   # MAC 地址
        ip_addr,                    # IP 地址
        'rd', f"{router_id}:{vni}", # Route Distinguisher
        'rt', f"{asn}:{vni}",       # Route Target
        'etag', '0',                 # ESI (单归)
        'label', str(vni),          # MPLS 标签 (通常等于 VNI)
        'nexthop', nexthop,                    # 网关 IP (通常是本机 VTEP IP)
    ]

    logger.info(f"Executing command: {' '.join(cmd)}")

    try:
        # 执行命令
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("EVPN Type-2 route announced successfully.")
        if result.stdout:
            logger.debug(f"gobgp stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"gobgp stderr: {result.stderr.strip()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to announce EVPN route. Command: {' '.join(e.cmd)}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        logger.error("gobgp command not found. Please ensure gobgp is installed and in PATH.")
    except Exception as e:
        logger.error(f"Unexpected error executing gobgp command: {e}")

def main():
    if len(sys.argv) != 3:
        logger.error("not enough arguments")
        return -1
    global ROUTER_ID1, ROUTER_ID2
    ROUTER_ID1 = sys.argv[1]
    ROUTER_ID2 = sys.argv[2]
    """主函数：启动两个工作线程"""
    try:
        # 1. 获取 br-vxlan 的 IP 和 MAC
        ip_mac = get_bridge_ip_and_mac(BRIDGE_IFNAME)
        if not ip_mac:
            logger.error("Failed to get IP and MAC address. Exiting.")
            return

        ip_addr, mac_addr = ip_mac
        # 2. 宣告 EVPN 路由
        announce_evpn_route(ip_addr, mac_addr, ASN1, VNI, ROUTER_ID1, GRPC_ENDPOINTS[0]['port'])
        announce_evpn_route(ip_addr, mac_addr, ASN2, VNI, ROUTER_ID2, GRPC_ENDPOINTS[1]['port'])

        # 创建两个线程
        thread1 = threading.Thread(
            target=worker_thread,
            args=(GRPC_ENDPOINTS[0], 'thread1'),
            name='grpc1-thread'
        )
        thread2 = threading.Thread(
            target=worker_thread,
            args=(GRPC_ENDPOINTS[1], 'thread2'),
            name='grpc2-thread'
        )

        # 启动线程
        thread1.start()
        thread2.start()

        logger.info("EVPN listeners started.")

        # 等待线程结束 (通常不会，除非 KeyboardInterrupt)
        thread1.join()
        thread2.join()

    except KeyboardInterrupt:
        logger.info("Main: Shutdown requested.")
    finally:
        ip.close()
        logger.info("Cleanup done.")


if __name__ == '__main__':
    main()
