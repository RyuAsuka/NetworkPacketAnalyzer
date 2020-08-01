"""
Flow
====

定义流的实体。

每一个流分为前后两个方向。当一个包到来时，会根据它的头部信息判断它属于前向包还是后向包。
每一个属于该流的数据包被加入该流时，相应的统计量会进行更新。
"""

from NetworkPacketAnalyzer.entities.BasicPacket import BasicPacket
from NetworkPacketAnalyzer.utils.logger import MyLogger
from NetworkPacketAnalyzer.analyzer.FlowStatistics import FlowStatistics
from NetworkPacketAnalyzer.utils.FlowStatus import FlowStatus


class Flow(object):
    """
    定义流。

    Attributes
    ----------
    logger: MyLogger
        用于记录日志。
    _forward: list of BasicPacket
        用于存放前向数据包。
    _backward: list of BasicPacket
        用于存放后向数据包。
    flow_id: str
        流 ID。格式：源 IP-源端口-目的IP-目的端口-协议号。
    src_ip: str
        流的源IP
    src_port: int
        流的源端口
    dst_ip: str
        流的目的IP
    dst_port: int
        流的目的端口
    protocol: int
        流的协议号（TCP=6，UDP=17，其他=0）
    start_time: int
        流的起始时间（微秒）
    end_time: int
        流的结束时间（微秒）
    flow_timeout: int
        流超时时间（微秒）
    packet_length_stats: FlowStatistics
        统计流中所有包的总长度的统计量。
    packet_header_length_stats: FlowStatistics
        统计流中头部总长度的统计量。
    packet_payload_length_stats: FlowStatistics
        统计流中负载总长度的统计量。
    forward_packet_length_stats: FlowStatistics
        统计前向流中包的总长度的统计量。
    forward_packet_header_length_stats: FlowStatistics
        统计前向流中包的头部总长度的统计量。
    forward_packet_payload_length_stats: FlowStatistics
        统计前向流中包的负载总长度的统计量。
    forward_packet_interval_stats: FlowStatistics
        统计前向流中包的间隔时间的统计量。
    backward_packet_length_stats: FlowStatistics
        统计后向流中包的总长度的统计量。
    backward_packet_header_length_stats: FlowStatistics
        统计后向流中包的头部总长度的统计量。
    backward_packet_payload_length_stats: FlowStatistics
        统计后向流中包的负载总长度的统计量。
    backward_packet_interval_stats: FlowStatistics
        统计后向流中包的间隔时间的统计量。


    Parameters
    ----------
    first_packet: BasicPacket
        该流的第一个包，用于构造流
    flow_timeout: int
        指定流超时时间
    """
    def __init__(self, first_packet, flow_timeout):
        self.logger = MyLogger('Flow')
        self._forward = []
        self._backward = []
        self.start_time = 0
        self.end_time = 0
        self.flow_timeout = flow_timeout

        # 统计量
        self.packet_length_stats = FlowStatistics()
        self.packet_header_length_stats = FlowStatistics()
        self.packet_payload_length_stats = FlowStatistics()
        self.packet_interval_stats = FlowStatistics()

        self.forward_packet_length_stats = FlowStatistics()
        self.forward_packet_header_length_stats = FlowStatistics()
        self.forward_packet_payload_length_stats = FlowStatistics()
        self.forward_packet_interval_stats = FlowStatistics()

        self.backward_packet_length_stats = FlowStatistics()
        self.backward_packet_header_length_stats = FlowStatistics()
        self.backward_packet_payload_length_stats = FlowStatistics()
        self.backward_packet_interval_stats = FlowStatistics()

        self.flow_status = FlowStatus.ACTIVE

        self.flow_id = self._add_first_packet(first_packet)
        self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol = self._parse_flow_id()

    def _parse_flow_id(self):
        """
        若流ID 存在，将流 ID 对应的源IP、源端口、目的IP、目的端口、协议号解析出来并放入相应参数中。

        Returns
        -------
        tuple(str, int, str, int, int):
            分别返回源IP、源端口、目的IP、目的端口、协议号。
        """
        if self.flow_id:
            split_id = self.flow_id.split('-')
            return split_id[0], int(split_id[1]), split_id[2], int(split_id[3]), int(split_id[4])
        else:
            return "", 0, "", 0, 0

    def _add_first_packet(self, packet):
        """
        当流为空流时，第一个到达的数据包触发该方法。

        Parameters
        ----------
        packet: BasicPacket
            流中第一个包。

        Returns
        -------
        str:
            第一个包对应的 Flow ID.
        """
        self._forward.append(packet)
        self.start_time = packet.timestamp
        self.end_time = packet.timestamp

        self.packet_length_stats.add_value(packet.total_size)
        self.packet_header_length_stats.add_value(packet.header_size)
        self.packet_payload_length_stats.add_value(packet.payload_size)

        self.forward_packet_length_stats.add_value(packet.total_size)
        self.forward_packet_header_length_stats.add_value(packet.header_size)
        self.forward_packet_payload_length_stats.add_value(packet.payload_size)

        return packet.forward_flow_id()

    def add_packet(self, packet):
        """
        向流中添加包，并更新流信息

        Parameters
        ----------
        packet: BasicPacket
            待添加的 IP 包。
        """
        if not packet:
            return
        if packet.forward_flow_id() == self.flow_id:
            self._forward.append(packet)
            self.forward_packet_length_stats.add_value(packet.total_size)
            self.forward_packet_header_length_stats.add_value(packet.header_size)
            self.forward_packet_payload_length_stats.add_value(packet.payload_size)
        elif packet.backward_flow_id() == self.flow_id:
            self._backward.append(packet)
            self.backward_packet_length_stats.add_value(packet.total_size)
            self.backward_packet_header_length_stats.add_value(packet.header_size)
            self.backward_packet_payload_length_stats.add_value(packet.payload_size)

        self.packet_length_stats.add_value(packet.total_size)
        self.packet_header_length_stats.add_value(packet.header_size)
        self.packet_payload_length_stats.add_value(packet.payload_size)
        self.end_time = packet.timestamp
        interval = self.end_time - self.start_time
        self.packet_interval_stats.add_value(interval)
        if packet.forward_flow_id() == self.flow_id:
            self.forward_packet_interval_stats.add_value(interval)
        elif packet.backward_flow_id() == self.flow_id:
            self.backward_packet_interval_stats.add_value(interval)

    @property
    def flow_duration(self):
        return self.end_time - self.start_time

    @property
    def total_packet_length(self):
        return self.packet_length_stats.sum()

    @property
    def min_packet_length(self):
        return self.packet_length_stats.min()

    @property
    def max_packet_length(self):
        return self.packet_length_stats.max()

    @property
    def mean_packet_length(self):
        return self.packet_length_stats.mean()

    @property
    def std_packet_length(self):
        return self.packet_length_stats.std()

    @property
    def total_forward_packet_length(self):
        return self.forward_packet_length_stats.sum()

    @property
    def min_forward_packet_length(self):
        return self.forward_packet_length_stats.min()

    @property
    def max_forward_packet_length(self):
        return self.forward_packet_length_stats.max()

    @property
    def mean_forward_packet_length(self):
        return self.forward_packet_length_stats.mean()

    @property
    def std_forward_packet_length(self):
        return self.forward_packet_length_stats.std()

    @property
    def total_backward_packet_length(self):
        return self.backward_packet_length_stats.sum()

    @property
    def min_backward_packet_length(self):
        return self.backward_packet_length_stats.min()

    @property
    def max_backward_packet_length(self):
        return self.backward_packet_length_stats.max()

    @property
    def mean_backward_packet_length(self):
        return self.backward_packet_length_stats.mean()

    @property
    def std_backward_packet_length(self):
        return self.backward_packet_length_stats.std()

    @property
    def total_forward_packet_header_length(self):
        return self.forward_packet_header_length_stats.sum()

    @property
    def min_forward_packet_header_length(self):
        return self.forward_packet_header_length_stats.min()

    @property
    def max_forward_packet_header_length(self):
        return self.forward_packet_header_length_stats.max()

    @property
    def mean_forward_packet_header_length(self):
        return self.forward_packet_header_length_stats.mean()

    @property
    def std_forward_packet_header_length(self):
        return self.forward_packet_header_length_stats.std()

    @property
    def total_backward_packet_header_length(self):
        return self.backward_packet_header_length_stats.sum()

    @property
    def min_backward_packet_header_length(self):
        return self.backward_packet_header_length_stats.min()

    @property
    def max_backward_packet_header_length(self):
        return self.backward_packet_header_length_stats.max()

    @property
    def mean_backward_packet_header_length(self):
        return self.backward_packet_header_length_stats.mean()

    @property
    def std_backward_packet_header_length(self):
        return self.backward_packet_header_length_stats.std()

    @property
    def total_forward_packet_payload_length(self):
        return self.forward_packet_header_length_stats.sum()

    @property
    def min_forward_packet_payload_length(self):
        return self.forward_packet_header_length_stats.min()

    @property
    def max_forward_packet_payload_length(self):
        return self.forward_packet_header_length_stats.max()

    @property
    def mean_forward_packet_payload_length(self):
        return self.forward_packet_header_length_stats.mean()

    @property
    def std_forward_packet_payload_length(self):
        return self.forward_packet_header_length_stats.std()

    @property
    def total_backward_packet_payload_length(self):
        return self.backward_packet_header_length_stats.sum()

    @property
    def min_backward_packet_payload_length(self):
        return self.backward_packet_header_length_stats.min()

    @property
    def max_backward_packet_payload_length(self):
        return self.backward_packet_header_length_stats.max()

    @property
    def mean_backward_packet_payload_length(self):
        return self.backward_packet_header_length_stats.mean()

    @property
    def std_backward_packet_payload_length(self):
        return self.backward_packet_header_length_stats.std()

    @property
    def packet_count(self):
        return len(self._forward) + len(self._backward)

    @property
    def forward_packet_count(self):
        return len(self._forward)

    @property
    def backward_packet_count(self):
        return len(self._backward)

    @property
    def packet_rate(self):
        if self.flow_duration == 0:
            return 1
        return (len(self._forward) + len(self._backward)) / self.flow_duration

    @property
    def forward_packet_rate(self):
        if self.flow_duration == 0:
            return 1
        return len(self._forward) / self.flow_duration

    @property
    def backward_packet_rate(self):
        if self.flow_duration == 0:
            return 1
        return len(self._backward) / self.flow_duration

    @property
    def bytes_rate(self):
        if self.flow_duration == 0:
            return self.total_packet_length
        return self.total_packet_length / self.flow_duration

    @property
    def forward_bytes_rate(self):
        if self.flow_duration == 0:
            return self.total_forward_packet_length
        return self.total_forward_packet_length / self.flow_duration

    @property
    def backward_bytes_rate(self):
        if self.flow_duration == 0:
            return self.total_forward_packet_length
        return self.total_backward_packet_length / self.flow_duration

    @property
    def tcp_flags(self):
        syn_count = 0
        ack_count = 0
        rst_count = 0
        urg_count = 0
        psh_count = 0
        fin_count = 0
        for fp in self._forward:
            fp: BasicPacket
            if fp.hasURG:
                urg_count += 1
            if fp.hasSYN:
                syn_count += 1
            if fp.hasRST:
                rst_count += 1
            if fp.hasACK:
                ack_count += 1
            if fp.hasPSH:
                psh_count += 1
            if fp.hasFIN:
                fin_count += 1
        for bp in self._forward:
            bp: BasicPacket
            if bp.hasURG:
                urg_count += 1
            if bp.hasSYN:
                syn_count += 1
            if bp.hasRST:
                rst_count += 1
            if bp.hasACK:
                ack_count += 1
            if bp.hasPSH:
                psh_count += 1
            if bp.hasFIN:
                fin_count += 1
        return syn_count, ack_count, rst_count, urg_count, psh_count, fin_count

    @property
    def init_window_size(self):
        return self._forward[0].window_size

    @property
    def min_packet_interval(self):
        return self.packet_interval_stats.min()

    @property
    def max_packet_interval(self):
        return self.packet_interval_stats.max()

    @property
    def mean_packet_interval(self):
        return self.packet_interval_stats.mean()

    @property
    def std_packet_interval(self):
        return self.packet_interval_stats.std()

    @property
    def min_forward_packet_interval(self):
        return self.forward_packet_interval_stats.min()

    @property
    def max_forward_packet_interval(self):
        return self.forward_packet_interval_stats.max()

    @property
    def mean_forward_packet_interval(self):
        return self.forward_packet_interval_stats.mean()

    @property
    def std_forward_packet_interval(self):
        return self.forward_packet_interval_stats.std()

    @property
    def min_backward_packet_interval(self):
        return self.backward_packet_interval_stats.min()

    @property
    def max_backward_packet_interval(self):
        return self.backward_packet_interval_stats.max()

    @property
    def mean_backward_packet_interval(self):
        return self.backward_packet_interval_stats.mean()

    @property
    def std_backward_packet_interval(self):
        return self.backward_packet_interval_stats.std()
