"""
This module defines the flow entity.

Every flow is divided to two directions, forward and backward.
When a packet comes, it is judged by its header information and
classified to forward packet and backward packet.

When every packet belongs to this flow joined, the related statistics
will be updated.
"""

import time
from entities.BasicPacket import BasicPacket
from utils.logger import MyLogger
from analyzer.FlowStatistics import FlowStatistics
from utils.FlowStatus import FlowStatus

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class Flow(object):
    """
    The flow entity.

    Attributes
    ----------
    logger: MyLogger
        The logger to log the processing.
    _forward: list of BasicPacket
        A list to save forward packets.
    _backward: list of BasicPacket
        A list to save backward packets.
    flow_id: str
        The flow id with format "SrcIP-SrcPort-DstIP-DstPort-Protocol"
    src_ip: str
        The source IP of the flow.
    src_port: int
        The source port of the flow.
    dst_ip: str
        The destination IP of the flow.
    dst_port: int
        The destination Port of the flow.
    protocol: int
        The protocol number of the flow. (TCP=6, UDP=17, Others=0)
    start_timestamp: int
        The start time of the flow. (in microseconds)
    end_timestamp: int
        The end time of the flow. (in microseconds)
    flow_timeout: int
        The timeout of the flow. (in microsecons)
    packet_length_stats: FlowStatistics
        The statistics of packet length in the flow.
    packet_header_length_stats: FlowStatistics
        The statistics of packet header length in the flow.
    packet_payload_length_stats: FlowStatistics
        The statistics of packet payload length in the flow.
    forward_packet_length_stats: FlowStatistics
        The statistics of forward packet length in the flow.
    forward_packet_header_length_stats: FlowStatistics
        The statistics of forward packet header length in the flow.
    forward_packet_payload_length_stats: FlowStatistics
        The statistics of forward packet payload length in the flow.
    forward_packet_interval_stats: FlowStatistics
        The statistics of forward packet interval in the flow.
    backward_packet_length_stats: FlowStatistics
        The statistics of backward packet length in the flow.
    backward_packet_header_length_stats: FlowStatistics
        The statistics of backward packet header length in the flow.
    backward_packet_payload_length_stats: FlowStatistics
        The statistics of backward packet payload length in the flow.
    backward_packet_interval_stats: FlowStatistics
        The statistics of backward packet interval in the flow.
    flow_status : int
        Current flow status.


    Parameters
    ----------
    first_packet : BasicPacket
        The first packet of this flow, which used to construct the flow.
    flow_timeout : int
        The flow timeout.

    See Also
    --------
    FlowStatus : The flow status enum.
    """

    def __init__(self, first_packet, flow_timeout):
        self.logger = MyLogger('Flow')
        self._forward = []
        self._backward = []
        self.start_timestamp = 0
        self.end_timestamp = 0
        self.flow_timeout = flow_timeout

        # Statistics
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
        Parse the basic 5-tuple from flow ID.

        If the flow ID exists, it will be extracted to SrcIP, SrcPort, DstIP, DstPort and protocols, and they will
        be put into the corresponding attributes.

        Returns
        -------
        tuple of (str, int, str, int, int):
            Returns SrcIP, SrcPort, DstIP, DstPort, protocol.
        """
        if self.flow_id:
            split_id = self.flow_id.split('-')
            return split_id[0], int(split_id[1]), split_id[2], int(split_id[3]), int(split_id[4])
        else:
            return "", 0, "", 0, 0

    def _add_first_packet(self, packet):
        """
        Add the first packet into a flow.

        This method should only invoke once when the flow is empty.

        Parameters
        ----------
        packet: BasicPacket
            The first packet of the flow.

        Returns
        -------
        str:
            The flow ID of the first packet.
        """
        self._forward.append(packet)
        self.start_timestamp = packet.timestamp
        self.end_timestamp = packet.timestamp

        self.packet_length_stats.add_value(packet.total_size)
        self.packet_header_length_stats.add_value(packet.header_size)
        self.packet_payload_length_stats.add_value(packet.payload_size)

        self.forward_packet_length_stats.add_value(packet.total_size)
        self.forward_packet_header_length_stats.add_value(packet.header_size)
        self.forward_packet_payload_length_stats.add_value(packet.payload_size)

        return packet.forward_flow_id()

    def add_packet(self, packet):
        """
        Add the packet into the flow and update informations.

        Parameters
        ----------
        packet: BasicPacket
            The packet to be added.
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
        self.end_timestamp = packet.timestamp
        interval = self.end_timestamp - self.start_timestamp
        self.packet_interval_stats.add_value(interval)
        if packet.forward_flow_id() == self.flow_id:
            self.forward_packet_interval_stats.add_value(interval)
        elif packet.backward_flow_id() == self.flow_id:
            self.backward_packet_interval_stats.add_value(interval)

    @staticmethod
    def _get_formatted_time_string(microseconds, time_format):
        """
        Generate the formatted time string.

        The time string is formatted by built-in `time` module.

        Parameters
        ----------
        microseconds : int
            The microseconds of needed time.
        time_format : str
            The time string format.

        Returns
        -------
        str
            The converted time string.

        See Also
        --------
        time : The `time` module.
        """
        mic_sec = microseconds % 1000000
        sec = microseconds / 1000000
        time_str = time.strftime(time_format, time.gmtime(sec))
        return time_str + str(mic_sec)

    @property
    def start_time(self):
        """
        Returns the formatted start time.

        The formatted time could make the time readable.
        The time format is passed through `time_format` string.

        Returns
        -------
        str
            The string format of start time.
        """
        return self._get_formatted_time_string(self.start_timestamp, TIME_FORMAT)

    @property
    def end_time(self):
        """
        Returns the formatted end time.

        Returns
        -------
        str
            The string format of end time.
        """
        return self._get_formatted_time_string(self.end_timestamp, TIME_FORMAT)

    @property
    def flow_duration(self):
        """
        Returns the flow duration.

        Returns
        -------
        int
            The flow duration.
        """
        return self.end_timestamp - self.start_timestamp

    @property
    def total_packet_length(self):
        """
        Returns the total packet length.

        Returns
        -------
        int
            Total packet length.
        """
        return self.packet_length_stats.sum()

    @property
    def min_packet_length(self):
        """
        Returns the minimum packet length of all packets.

        Returns
        -------
        int
            The minimum packet length.
        """
        return self.packet_length_stats.min()

    @property
    def max_packet_length(self):
        """
        Returns the maximum packet length of all packets.

        Returns
        -------
        int
            The maximum packet length.
        """
        return self.packet_length_stats.max()

    @property
    def mean_packet_length(self):
        """
        Returns the average packet length of all packets.

        Returns
        -------
        int
            The average packet length.
        """
        return self.packet_length_stats.mean()

    @property
    def std_packet_length(self):
        """
        Returns the standard deviation of packet length of all packets.

        Returns
        -------
        int
            The standard deviation of packet length.
        """
        return self.packet_length_stats.std()

    @property
    def total_forward_packet_length(self):
        """
        Returns the packet length of forward packets.

        Returns
        -------
        int
            The total forward packet length.
        """
        return self.forward_packet_length_stats.sum()

    @property
    def min_forward_packet_length(self):
        """
        Returns the minimum packet length of forward packets.

        Returns
        -------
        int
            The minimum packet length.
        """
        return self.forward_packet_length_stats.min()

    @property
    def max_forward_packet_length(self):
        """
        Returns the maximum packet length of forward packets.

        Returns
        -------
        int
            The maximum packet length.
        """
        return self.forward_packet_length_stats.max()

    @property
    def mean_forward_packet_length(self):
        """
        Returns the average packet length of forward packets.

        Returns
        -------
        int
            The average packet length.
        """
        return self.forward_packet_length_stats.mean()

    @property
    def std_forward_packet_length(self):
        """
        Returns the standard deviation of packet length of forward packets.

        Returns
        -------
        int
            The standard deviation of packet length.
        """
        return self.forward_packet_length_stats.std()

    @property
    def total_backward_packet_length(self):
        """
        Returns the packet length of backward packets.

        Returns
        -------
        int
            The total backward packet length.
        """
        return self.backward_packet_length_stats.sum()

    @property
    def min_backward_packet_length(self):
        """
        Returns the mininum packet length of backward packets.

        Returns
        -------
        int
            The minimum backward packet length.
        """
        return self.backward_packet_length_stats.min()

    @property
    def max_backward_packet_length(self):
        """
        Returns the maximum packet length of backward packets.

        Returns
        -------
        int
            The maximum backward packet length.
        """
        return self.backward_packet_length_stats.max()

    @property
    def mean_backward_packet_length(self):
        """
        Returns the average packet length of backward packets.

        Returns
        -------
        int
            The average backward packet length.
        """
        return self.backward_packet_length_stats.mean()

    @property
    def std_backward_packet_length(self):
        """
        Returns the standard deviation of packet length of backward packets.

        Returns
        -------
        int
            The standard deviation of backward packet length.
        """
        return self.backward_packet_length_stats.std()

    @property
    def total_forward_packet_header_length(self):
        """
        Returns the header length of forward packets.

        Returns
        -------
        int
            The forward header length.
        """
        return self.forward_packet_header_length_stats.sum()

    @property
    def min_forward_packet_header_length(self):
        """
        Returns the minimum of header length of forward packets.

        Returns
        -------
        int
            The minimum forward header length.
        """
        return self.forward_packet_header_length_stats.min()

    @property
    def max_forward_packet_header_length(self):
        """
        Returns the maximum of header length of forward packets.

        Returns
        -------
        int
            The maximum forward header length.
        """
        return self.forward_packet_header_length_stats.max()

    @property
    def mean_forward_packet_header_length(self):
        """
        Returns the average of header length of forward packets.

        Returns
        -------
        int
            The average forward header length.
        """
        return self.forward_packet_header_length_stats.mean()

    @property
    def std_forward_packet_header_length(self):
        """
        Returns the standard deviation of header length of forward packets.

        Returns
        -------
        int
            The standard deviation  forward header length.
        """
        return self.forward_packet_header_length_stats.std()

    @property
    def total_backward_packet_header_length(self):
        """
        Returns the header length of backward packets.

        Returns
        -------
        int
            The backward header length.
        """
        return self.backward_packet_header_length_stats.sum()

    @property
    def min_backward_packet_header_length(self):
        """
        Returns the minimum of header length of backward packets.

        Returns
        -------
        int
            The minimum backward header length.
        """
        return self.backward_packet_header_length_stats.min()

    @property
    def max_backward_packet_header_length(self):
        """
        Returns the maximum of header length of backward packets.

        Returns
        -------
        int
            The maximum backward header length.
        """
        return self.backward_packet_header_length_stats.max()

    @property
    def mean_backward_packet_header_length(self):
        """
        Returns the average of header length of backward packets.

        Returns
        -------
        int
            The average backward header length.
        """
        return self.backward_packet_header_length_stats.mean()

    @property
    def std_backward_packet_header_length(self):
        """
        Returns the standard deviation of header length of backward packets.

        Returns
        -------
        int
            The standard deviation of backward header length.
        """
        return self.backward_packet_header_length_stats.std()

    @property
    def total_forward_packet_payload_length(self):
        """
        Returns the payload length of forward packets.

        Returns
        -------
        int
            The forward forward payload length.
        """
        return self.forward_packet_header_length_stats.sum()

    @property
    def min_forward_packet_payload_length(self):
        """
        Returns the minimum payload length of forward packets.

        Returns
        -------
        int
            The minimum forward payload length.
        """
        return self.forward_packet_header_length_stats.min()

    @property
    def max_forward_packet_payload_length(self):
        """
        Returns the maximum payload length of forward packets.

        Returns
        -------
        int
            The maximum forward payload length.
        """
        return self.forward_packet_header_length_stats.max()

    @property
    def mean_forward_packet_payload_length(self):
        """
        Returns the average payload length of forward packets.

        Returns
        -------
        int
            The average forward payload length.
        """
        return self.forward_packet_header_length_stats.mean()

    @property
    def std_forward_packet_payload_length(self):
        """
        Returns the standard deviation of payload length of forward packets.

        Returns
        -------
        int
            The standard deviation of forward payload length.
        """
        return self.forward_packet_header_length_stats.std()

    @property
    def total_backward_packet_payload_length(self):
        """
        Returns the payload length of backward packets.

        Returns
        -------
        int
            The backward payload length.
        """
        return self.backward_packet_header_length_stats.sum()

    @property
    def min_backward_packet_payload_length(self):
        """
        Returns the minimum payload length of backward packets.

        Returns
        -------
        int
            The minimum backward payload length.
        """
        return self.backward_packet_header_length_stats.min()

    @property
    def max_backward_packet_payload_length(self):
        """
        Returns the maximum payload length of backward packets.

        Returns
        -------
        int
            The maximum backward payload length.
        """
        return self.backward_packet_header_length_stats.max()

    @property
    def mean_backward_packet_payload_length(self):
        """
        Returns the average payload length of backward packets.

        Returns
        -------
        int
            The average backward payload length.
        """
        return self.backward_packet_header_length_stats.mean()

    @property
    def std_backward_packet_payload_length(self):
        """
        Returns the standard deviation of payload length of backward packets.

        Returns
        -------
        int
            The standard deviation of backward payload length.
        """
        return self.backward_packet_header_length_stats.std()

    @property
    def packet_count(self):
        """
        Returns the number of packets in the whole flow.

        Returns
        -------
        int
            The full packet counts.
        """
        return len(self._forward) + len(self._backward)

    @property
    def forward_packet_count(self):
        """
        Returns the number of packets in the forward flow.

        Returns
        -------
        int
            The forward packet counts.
        """
        return len(self._forward)

    @property
    def backward_packet_count(self):
        """
        Returns the number of packets in the backward flow.

        Returns
        -------
        int
            The backward packet counts.
        """
        return len(self._backward)

    @property
    def packet_rate(self):
        """
        Returns the number of packets per second in the whole flow.

        Returns
        -------
        float
            The number of packets per second.
        """
        if self.flow_duration == 0:
            return 1
        return (len(self._forward) + len(self._backward)) / (self.flow_duration / 1000000)

    @property
    def forward_packet_rate(self):
        """
        Returns the number of packets per second in the forward flow.

        Returns
        -------
        float
            The number of packets per second.
        """
        if self.flow_duration == 0:
            return 1
        return len(self._forward) / (self.flow_duration / 1000000)

    @property
    def backward_packet_rate(self):
        """
        Returns the number of packets per second in the backward flow.

        Returns
        -------
        float
            The number of packets per second.
        """
        if self.flow_duration == 0:
            return 1
        return len(self._backward) / (self.flow_duration / 1000000)

    @property
    def bytes_rate(self):
        """
        Returns the number of bytes per second in the whole flow.

        Returns
        -------
        float
            The number of bytes per second.
        """
        if self.flow_duration == 0:
            return self.total_packet_length
        return self.total_packet_length / (self.flow_duration / 1000000)

    @property
    def forward_bytes_rate(self):
        """
        Returns the number of bytes per second in the forward flow.

        Returns
        -------
        float
            The number of bytes per second.
        """
        if self.flow_duration == 0:
            return self.total_forward_packet_length
        return self.total_forward_packet_length / (self.flow_duration / 1000000)

    @property
    def backward_bytes_rate(self):
        """
        Returns the number of bytes per second in the backward flow.

        Returns
        -------
        float
            The number of bytes per second.
        """
        if self.flow_duration == 0:
            return self.total_forward_packet_length
        return self.total_backward_packet_length / (self.flow_duration / 1000000)

    @staticmethod
    def _stat_flags(packets_list):
        """
        Statistic the flag count in all packets.

        Parameters
        ----------
        packets_list : list of BasicPacket
            The packet list.

        Returns
        -------
        syn_count : int
            The number of SYN flags.
        ack_count : int
            The number of ACK flags.
        rst_count : int
            The number of RST flags.
        urg_count : int
            The number of URG flags.
        psh_count : int
            The number of PSH flags.
        fin_count : int
            The number of FIN flags.
        """
        syn_count = 0
        ack_count = 0
        rst_count = 0
        urg_count = 0
        psh_count = 0
        fin_count = 0
        for pkt in packets_list:
            if pkt.hasURG:
                urg_count += 1
            if pkt.hasSYN:
                syn_count += 1
            if pkt.hasRST:
                rst_count += 1
            if pkt.hasACK:
                ack_count += 1
            if pkt.hasPSH:
                psh_count += 1
            if pkt.hasFIN:
                fin_count += 1
        return syn_count, ack_count, rst_count, urg_count, psh_count, fin_count

    @property
    def tcp_flags(self):
        """
        Returns the tcp flags count. (Only for TCP packets)

        Returns
        -------
        syn_count : int
            The number of SYN flags.
        ack_count : int
            The number of ACK flags.
        rst_count : int
            The number of RST flags.
        urg_count : int
            The number of URG flags.
        psh_count : int
            The number of PSH flags.
        fin_count : int
            The number of FIN flags.
        """
        forward_flags = self._stat_flags(self._forward)
        backward_flags = self._stat_flags(self._backward)
        return forward_flags[0] + backward_flags[0], \
            forward_flags[1] + backward_flags[1], \
            forward_flags[2] + backward_flags[2], \
            forward_flags[3] + backward_flags[3], \
            forward_flags[4] + backward_flags[4], \
            forward_flags[5] + backward_flags[5]

    @property
    def init_window_size(self):
        """
        Returns the initial window size of the first packet in the flow. (Only for TCP)

        Returns
        -------
        int
            The first window size.
        """
        return self._forward[0].window_size

    @property
    def min_packet_interval(self):
        """
        Returns the minimum interval of packet arriving in both side.

        Returns
        -------
        int
            The minimum packet interval.
        """
        return self.packet_interval_stats.min()

    @property
    def max_packet_interval(self):
        """
        Returns the maximum interval of packet arriving in both side.

        Returns
        -------
        int
            The maximum packet interval.
        """
        return self.packet_interval_stats.max()

    @property
    def mean_packet_interval(self):
        """
        Returns the average interval of packet arriving in both side.

        Returns
        -------
        int
            The average packet interval.
        """
        return self.packet_interval_stats.mean()

    @property
    def std_packet_interval(self):
        """
        Returns the standard deviation of interval of packet arriving in both side.

        Returns
        -------
        int
            The standard deviation of packet interval.
        """
        return self.packet_interval_stats.std()

    @property
    def min_forward_packet_interval(self):
        """
        Returns the minimum interval of packet arriving in forward.

        Returns
        -------
        int
            The minimum forward  packet interval.
        """
        return self.forward_packet_interval_stats.min()

    @property
    def max_forward_packet_interval(self):
        """
        Returns the maximum interval of packet arriving in forward.

        Returns
        -------
        int
            The maximum forward packet interval.
        """
        return self.forward_packet_interval_stats.max()

    @property
    def mean_forward_packet_interval(self):
        """
        Returns the average interval of packet arriving in forward.

        Returns
        -------
        int
            The average forward  packet interval.
        """
        return self.forward_packet_interval_stats.mean()

    @property
    def std_forward_packet_interval(self):
        """
        Returns the standard deviation of interval of packet arriving in forward.

        Returns
        -------
        int
            The standard deviation of forward packet interval.
        """
        return self.forward_packet_interval_stats.std()

    @property
    def min_backward_packet_interval(self):
        """
        Returns the minimum interval of packet arriving in backward.

        Returns
        -------
        int
            The minimum backward  packet interval.
        """
        return self.backward_packet_interval_stats.min()

    @property
    def max_backward_packet_interval(self):
        """
        Returns the maximum interval of packet arriving in backward.

        Returns
        -------
        int
            The maximum backward packet interval.
        """
        return self.backward_packet_interval_stats.max()

    @property
    def mean_backward_packet_interval(self):
        """
        Returns the average interval of packet arriving in backward.

        Returns
        -------
        int
            The average backward packet interval.
        """
        return self.backward_packet_interval_stats.mean()

    @property
    def std_backward_packet_interval(self):
        """
        Returns the standard deviation of interval of packet arriving in backward.

        Returns
        -------
        int
            The standard deviation of backward packet interval.
        """
        return self.backward_packet_interval_stats.std()
