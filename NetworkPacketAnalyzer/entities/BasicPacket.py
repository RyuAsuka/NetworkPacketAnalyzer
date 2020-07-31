from scapy.layers.inet import IP


class BasicPacket(object):
    """
    定义基础数据包类。

    Parameters
    ----------
    packet_id: int
        数据包的全局 id
    timestamp: int
        数据包的到达时间（单位为微秒）
    ip_packet: IP
        数据包的网络层以上所有字段，含负载
    """
    def __init__(self, packet_id, timestamp, ip_packet):
        self.packet_id = packet_id
        self.timestamp = timestamp

        # IP information
        self.src_ip = ip_packet.src
        self.dst_ip = ip_packet.dst
        self.protocol = ip_packet.protocol

        self.src_port = 0
        self.dst_port = 0
        self.hasACK = False
        self.hasFIN = False
        self.hasPSH = False
        self.hasRST = False
        self.hasSYN = False
        self.hasURG = False
        self.window_size = 0
        self.header_size = 0
        self.payload_size = 0

        if 'TCP' in ip_packet:
            tcp_layer_info = ip_packet['TCP']
            self.src_port = tcp_layer_info.sport
            self.dst_port = tcp_layer_info.dport
            if 'S' in tcp_layer_info.flags:
                self.hasSYN = True
            if 'A' in tcp_layer_info.flags:
                self.hasACK = True
            if 'F' in tcp_layer_info.flags:
                self.hasFIN = True
            if 'P' in tcp_layer_info.flags:
                self.hasPSH = True
            if 'U' in tcp_layer_info.flags:
                self.hasURG = True
            if 'R' in tcp_layer_info.flags:
                self.hasRST = True
            self.window_size = tcp_layer_info.window
        elif 'UDP' in ip_packet:
            udp_layer_info = ip_packet['UDP']
            self.src_port = udp_layer_info.sport
            self.dst_port = udp_layer_info.dport

        if 'Raw' in ip_packet:
            self.header_size = len(ip_packet) - len(ip_packet['Raw'])
            self.payload_size = len(ip_packet['Raw'])

        self.total_size = len(ip_packet)

    def forward_flow_id(self):
        """
        生成该流对应的前向流 ID。

        Returns
        -------
        str:
            该流对应的前向流 ID。
        """
        return '-'.join([self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol])

    def backward_flow_id(self):
        """
        生成该流对应的后向流 ID。

        Returns
        -------
        str:
            该流对应的后向流 ID。
        """
        return '-'.join([self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol])
