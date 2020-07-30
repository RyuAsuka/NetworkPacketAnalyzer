"""
定义了基本数据包信息类 BasicPacketInfo
"""


from utils.IdGenerator import IdGenerator
from scapy.layers.inet import IP


class BasicPacketInfo(object):
    """
    基本数据包信息类

    Parameters
    ----------
    id_generator: IdGenerator
        全局 ID 生成器。
    timestamp: int
        数据包到达的时间
    ip_packet: IP
        scapy.layers.inet.IP 对象。


    Attributes
    ----------
    id: int
        使用 IdGenerator 生成的全局 ID，表示该包在 pcap 文件中的顺序
    src_ip: str
        包的源 IP 地址。
    src_port: int
        包的源端口。
    dst_ip: str
        包的目的 IP 地址。
    dst_port: int
        包的目的端口
    protocol: int
        包的协议编号，其中 TCP 为 6，UDP 为 17，其他协议为 0
    timestamp: int
        表示包的时间戳。单位为微秒。
    payload_bytes: int
        表示包中负载部分的长度。
    flow_id: str
        表示该包所属流的 ID。
    flagFIN: boolean
        表示该包中是否含有 FIN 置位。
    flagPSH: boolean
        表示该包中是否含有 PSH 置位。
    flagURG: boolean
        表示该包中是否含有 URG 置位。
    flagSYN: boolean
        表示该包中是否含有 SYN 置位。
    flagACK: boolean
        表示该包中是否含有 ACK 置位。
    flagRST: boolean
        表示该包中是否含有 RST 置位。
    tcp_window: int
        表示该包中包含的 TCP 窗口大小。
    header_bytes: int
        表示该包中的头部字段大小。
    """
    def __init__(self, id_generator, timestamp, ip_packet=None):
        self.id = id_generator.next_id()
        self.src_ip = ""
        self.src_port = 0
        self.dst_ip = ""
        self.dst_port = 0
        self.protocol = 0
        self.timestamp = timestamp

        self.payload_bytes = 0
        self.flow_id = None
        self.flagFIN = False
        self.flagPSH = False
        self.flagURG = False
        self.flagSYN = False
        self.flagACK = False
        self.flagRST = False

        self.tcp_window = 0
        self.header_bytes = 0

        if ip_packet:
            self.src_ip = ip_packet.src
            self.src_port = ip_packet.sport
            self.dst_ip = ip_packet.dst
            self.dst_port = ip_packet.dport
            if 'TCP' in ip_packet:
                self.protocol = 6
                if 'F' in ip_packet['TCP'].flags:
                    self.flagFIN = True
                if 'P' in ip_packet['TCP'].flags:
                    self.flagPSH = True
                if 'U' in ip_packet['TCP'].flags:
                    self.flagURG = True
                if 'S' in ip_packet['TCP'].flags:
                    self.flagSYN = True
                if 'A' in ip_packet['TCP'].flags:
                    self.flagACK = True
                if 'R' in ip_packet['TCP'].flags:
                    self.flagRST = True
                self.tcp_window = ip_packet['TCP'].window
            elif 'UDP' in ip_packet:
                self.protocol = 17
            if 'Raw' in ip_packet:
                self.payload_bytes = len(ip_packet['Raw'])
            self.header_bytes = len(ip_packet) - len(ip_packet['Raw'])
            self.generate_flow_id(FlowDirection.FORWARD)

    def generate_flow_id(self, direction):
        """
        创建流 ID

        Parameters
        ----------
        direction: int
            只能为 FlowDirection.FORWARD 或 FlowDirection.BACKWARD。分别表示前向流和后向流。

        Returns
        -------
        str:
            返回该流的 ID。

        """
        if direction == FlowDirection.FORWARD:
            self.flow_id = '-'.join([self.src_ip, str(self.src_port), self.dst_ip, str(self.dst_port),
                                     str(self.protocol)])
        elif direction == FlowDirection.BACKWARD:
            self.flow_id = '-'.join([self.dst_ip, str(self.dst_port), self.src_ip, str(self.src_port),
                                     str(self.protocol)])
        return self.flow_id


class FlowDirection(object):
    """
    表示流方向的枚举类。
    """
    FORWARD = 0
    BACKWARD = 1
