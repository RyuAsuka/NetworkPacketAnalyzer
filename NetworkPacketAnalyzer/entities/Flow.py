"""
This module defines the flow entity.

Every flow is divided to two directions, forward and backward.
When a packet comes, it is judged by its header information and
classified to forward packet and backward packet.

When every packet belongs to this flow joined, the related statistics
will be updated.
"""

import time
from NetworkPacketAnalyzer.entities.BasicPacket import BasicPacket
from NetworkPacketAnalyzer.utils.logger import MyLogger
from NetworkPacketAnalyzer.analyzer.FlowStatistics import FlowStatistics
from NetworkPacketAnalyzer.utils.FlowStatus import FlowStatus


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
    _start_time: int
        The start time of the flow. (in microseconds)
    _end_time: int
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
        self._start_time = 0
        self._end_time = 0
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
        self._start_time = packet.timestamp
        self._end_time = packet.timestamp

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
        self._end_time = packet.timestamp
        interval = self._end_time - self._start_time
        self.packet_interval_stats.add_value(interval)
        if packet.forward_flow_id() == self.flow_id:
            self.forward_packet_interval_stats.add_value(interval)
        elif packet.backward_flow_id() == self.flow_id:
            self.backward_packet_interval_stats.add_value(interval)

    def _convert_time_format(self, time, format):
        """
        Convert time from microseconds to readable time format.

        Parameters
        ----------
        time : int
            The time int value (in microseconds).
        format : str
            The time format string.

        Returns
        -------
        str
            The converted time string.
        """

    @property
    def start_time(self):
        """
        Returns the flow start time in GMT standard format.

        The standard format is

            YYYY-mm-dd HH:MM:SS.microseconds

        Returns
        -------
        str
            The formatted string of time.
        """
        microseconds = self._start_time % 1000000
        time_sec = self._start_time / 1000000
        time_string = time.strftime("YYYY-mm-dd HH:MM:SS", time.gmtime(time_sec))
        return time_string + str(microseconds)

    @property
    def flow_duration(self):
        """
        Returns the flow duration.

        Returns
        -------
        int
            The flow duration.
        """
        return self.end_time - self.start_time

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
