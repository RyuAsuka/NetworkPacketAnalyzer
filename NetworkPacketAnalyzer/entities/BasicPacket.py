"""
This module defines the basic packet class.

The packet class is extracted from the IP object of `scapy.layers.inet.IP`.
"""


class BasicPacket(object):
    """
    The basic packet class.

    Parameters
    ----------
    packet_id : int
        The global ID of the packet.
    timestamp : int
        The arrival time of the packet. (in microsecond)
    ip_packet : scapy.layers.inet.IP
        The packet extracted from `scapy`.

    Attributes
    ----------
    packet_id : int
        The global ID of the packet.
    timestamp : int
        The arrival time of the packet. (in microsecond)
    src_ip : str
        The source IP of the packet.
    dst_ip : str
        The destination IP of the packet.
    protocol : int
        The procotol number of the packet. For TCP is 6, for UDP is 17, for others is 0.
    hasACK : bool
        True if the packet has flag "ACK".
    hasFIN : bool
        True if the packet has flag "FIN".
    hasRST : bool
        True if the packet has flag "RST".
    hasPSH : bool
        True if the packet has flag "PSH".
    hasSYN : bool
        True if the packet has flag "SYN".
    hasURG : bool
        True if the packet has flag "URG".
    window_size : int
        The initial window size in the packet. (Only for TCP)
    header_size : int
        The header size of the packet, including IP header and transportation layer header.
    payload_size : int
        The payload size of the packet.
    total_size : int
        The length of the whole packet. (Excluding the MAC layer header)
    """
    def __init__(self, packet_id, timestamp, ip_packet):
        self.packet_id = packet_id
        self.timestamp = timestamp

        # IP information
        self.src_ip = ip_packet.src
        self.dst_ip = ip_packet.dst
        self.protocol = ip_packet.proto

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
        Generate the forward flow ID of this packet.

        Returns
        -------
        str
            The forward flow ID.
        """
        return '-'.join([self.src_ip, str(self.src_port), self.dst_ip, str(self.dst_port), str(self.protocol)])

    def backward_flow_id(self):
        """
        Generate the backward flow ID of this packet.

        Returns
        -------
        str
            The backward flow ID.
        """
        return '-'.join([self.dst_ip, str(self.dst_port), self.src_ip, str(self.src_port), str(self.protocol)])
