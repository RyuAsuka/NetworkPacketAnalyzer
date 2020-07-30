"""
定义了基础流类。

该类中包含一个流的全部统计信息。
"""
from utils.FlowStatistics import FlowStatistics
from Entities.BasicPacketInfo import BasicPacketInfo


class BasicFlow(object):
    """
    定义了基础流类。

    该类中包含一个流的全部统计信息。

    Parameters
    ----------
    is_bidirectional: bool
        指向该流是否为双向流。
    packet: BasicPacketInfo
        要加入该流的包。
    src: str
        流的源 IP
    dst: str
        流的目的 IP
    src_port: int
        流的源端口
    dst_port: int
        流的目的端口
    activity_timeout: int
        流的活跃超时时间

    Attributes
    ----------
    
    """
    def __init__(self, is_bidirectional, packet, src="", dst="", src_port="", dst_port="", activity_timeout=0):

        self.is_bidirectional = is_bidirectional
        self.flag_counts = {}
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = 0
        self.flow_start_time = 0
        self.flow_last_time = 0
        self.flow_id = ""
        self.activity_timeout = activity_timeout
        # forward
        self.forward_pkt_stats = FlowStatistics()
        self.forward_pkts = []
        self.forward_bytes = 0
        self.foward_header_bytes = 0
        self.foward_psh_count = 0
        self.forward_urg_count = 0

        # backward
        self.backward_pkt_stats = FlowStatistics()
        self.backward_pkts = []
        self.backward_bytes = 0
        self.backward_header_bytes = 0
        self.backward_psh_count = 0
        self.backward_urg_count = 0

        self.flow_IAT = FlowStatistics()
        self.forward_IAT = FlowStatistics()
        self.backward_IAT = FlowStatistics()
        self.flow_length_stats = FlowStatistics()

        self.first_packet(packet)

    def packet_count(self):
        if self.is_bidirectional:
            return len(self.forward_pkts) + len(self.backward_pkts)
        else:
            return len(self.forward_pkts)

    # TODO: Implement function first_packet
    def first_packet(self, packet):
        pass

    # TODO: Implement function add_packet
    def add_packet(self, packet):
        pass

    # TODO: Implement function update_active_idle_time
    def update_active_idle_time(self, current_timestamp, flow_activity_timeout):
        pass
