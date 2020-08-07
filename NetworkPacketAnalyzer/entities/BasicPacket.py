"""
This module defines the basic packet class.

The packet class is extracted from the IP object of `scapy.layers.inet.IP`.
"""


from utils.logger import MyLogger
from scapy.layers.inet import IP


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
        self.logger = MyLogger('BasicPacket')
        self.packet_id = packet_id
        self.timestamp = timestamp

        # IP information
        self.src_ip = str(ip_packet.src)
        self.dst_ip = str(ip_packet.dst)
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

        self.total_size = len(ip_packet)

        if 'TCP' in ip_packet.payload:
            tcp_segment = ip_packet.payload
            self.src_port = tcp_segment.sport
            self.dst_port = tcp_segment.dport
            if 'U' in tcp_segment.flags:
                self.hasURG = True
            if 'A' in tcp_segment.flags:
                self.hasACK = True
            if 'P' in tcp_segment.flags:
                self.hasPSH = True
            if 'R' in tcp_segment.flags:
                self.hasRST = True
            if 'S' in tcp_segment.flags:
                self.hasSYN = True
            if 'F' in tcp_segment.flags:
                self.hasFIN = True
            self.window_size = tcp_segment.window
            self.payload_size = len(tcp_segment.payload)
        elif 'UDP' in ip_packet.payload:
            udp_user_datagram = ip_packet.payload
            self.src_port = udp_user_datagram.sport
            self.dst_port = udp_user_datagram.dport
            self.payload_size = len(udp_user_datagram.payload)
        else:
            payload = ip_packet.payload
            self.payload_size = len(payload)

        self.header_size = self.total_size - self.payload_size

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

    def __str__(self):
        ip_packet_string = f'<IP src={self.src_ip}, dst={self.dst_ip}>'
        if self.protocol == 6:
            trans_packet_string = f'<TCP sport={self.src_port}, dport={self.dst_port}, flags='
            if self.hasURG:
                trans_packet_string += 'U'
            if self.hasACK:
                trans_packet_string += 'A'
            if self.hasPSH:
                trans_packet_string += 'P'
            if self.hasRST:
                trans_packet_string += 'R'
            if self.hasSYN:
                trans_packet_string += 'S'
            if self.hasFIN:
                trans_packet_string += 'F'
            trans_packet_string += f', window={self.window_size}>'
        elif self.protocol == 17:
            trans_packet_string = f'<UDP sport={self.src_port}, dport={self.dst_port}>'
        else:
            trans_packet_string = ''

        payload_string = f'<payload length={self.payload_size}>'
        return ip_packet_string + '|' + trans_packet_string + '|' + payload_string
