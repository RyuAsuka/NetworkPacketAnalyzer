"""
Generate a flow supervisor.

The flow supervisor maintains two collection spaces, one represents the currently processing flows `current_flows`,
the other is the flows finished processing `finished_flows`.

When a flow is marked as "finished", it will be moved from `current_flows` to `finished_flows`.

Notes
-----
    The condition of finishing a flow:

    1. There is FIN packets in the flow. When the handshake of closing flow ends,
        the flow is considered as "finished". (Only for TCP)
    2. There is a RST packet in the flow. When the processor meets the RST packet,
        the flow is considered as "finished" immediately. (Only for TCP)
    3. Next packet of the same flow ID comes, but the arrival time exceeds the flow timeout,
        then the flow is considered as "finished", and the new packet is considered as a new flow. (For TCP and UDP)
"""


from tqdm import tqdm
from entities.Flow import Flow
from entities.BasicPacket import BasicPacket
from utils.logger import MyLogger
from utils.FlowStatus import FlowStatus


class FlowGenerator(object):
    """
    The flow generator class.

    It maintains two collection spaces, one represents the currently processing flows `current_flows`,
    the other is the flows finished processing `finished_flows`.

    Attributes
    ----------
    current_flows : dict of {str: Flow}
        The flows which are currently processing.
    finished_flows : list of Flow
        The flows which are considered as finished.
    flow_timeout : int
        The timeout of a flow.

    Parameters
    ----------
    flow_timeout: int
        The timeout of a flow.
    """
    def __init__(self, flow_timeout):
        self.current_flows = {}
        self.finished_flows = []
        self.flow_timeout = flow_timeout
        self.logger = MyLogger('FlowGenerator')

    def add_packet(self, packet):
        """
        Add the packet to current flow.

        Parameters
        ----------
        packet: BasicPacket
            The processed `BasicPacket` object.
        """
        if not packet:
            return
        forward_packet_flow_id = packet.forward_flow_id()
        backward_packet_flow_id = packet.backward_flow_id()
        current_timestamp = packet.timestamp
        if forward_packet_flow_id not in self.current_flows and backward_packet_flow_id not in self.current_flows:
            # A new flow begins
            self.current_flows[forward_packet_flow_id] = Flow(packet, self.flow_timeout)
        else:
            if forward_packet_flow_id in self.current_flows:
                flow = self.current_flows[forward_packet_flow_id]
            else:
                flow = self.current_flows[backward_packet_flow_id]

            # Under the status of ACTIVE:
            # 1. When received a packet and it is timeout, finish current flow and genenrate a new flow.
            # 2. When received a forward FIN packet, turn to FIN_WAIT_1 status.
            # 3. When received a backward FIN packet, turn to CLOSE_WAIT status.
            # 4. When received a RST packet, finish current flow.
            # 5. When received a normal packet, add the packet to current flow.
            if flow.flow_status == FlowStatus.ACTIVE:
                if current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)
                elif packet.hasFIN:
                    flow.add_packet(packet)
                    if packet.forward_flow_id() == flow.flow_id:
                        flow.flow_status = FlowStatus.FIN_WAIT_1
                    else:
                        flow.flow_status = FlowStatus.CLOSE_WAIT
                elif packet.hasRST:
                    self.logger.debug(f'Received a RST packet: {flow.flow_id}')
                    flow.add_packet(packet)
                    self._move_flow_from_current_to_finished(flow)
                else:
                    flow.add_packet(packet)
            elif flow.flow_status == FlowStatus.FIN_WAIT_1:
                flow.add_packet(packet)
                if packet.hasFIN:
                    flow.flow_status = FlowStatus.CLOSING
                else:
                    flow.flow_status = FlowStatus.FIN_WAIT_2
            elif flow.flow_status == FlowStatus.FIN_WAIT_2:
                flow.add_packet(packet)
                if packet.hasFIN:
                    flow.flow_status = FlowStatus.TIME_WAIT
                elif current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.CLOSING:
                flow.add_packet(packet)
                if packet.hasACK:
                    self._move_flow_from_current_to_finished(flow)
                elif current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.CLOSE_WAIT:
                flow.add_packet(packet)
                if packet.backward_flow_id() == flow.flow_id and packet.hasFIN:
                    flow.flow_status = FlowStatus.LAST_ACK
                elif current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.LAST_ACK:
                flow.add_packet(packet)
                if packet.hasACK:
                    self._move_flow_from_current_to_finished(flow)
                elif current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.TIME_WAIT:
                if current_timestamp - flow.end_timestamp > self.flow_timeout:
                    self._timeout_process(flow, packet)

    def _move_flow_from_current_to_finished(self, flow):
        """
        Move the flow from `current_flows` to `finished_flows`.

        Parameters
        ----------
        flow: Flow
            The flow to be moved.
        """
        self.finished_flows.append(flow)
        if flow.flow_id in self.current_flows.keys():
            self.current_flows.pop(flow.flow_id)
        else:
            self.logger.warning("flow id %s is not in current_flows.keys()", flow.flow_id)
            self.logger.warning("Reverse the flow ID.")
            self.current_flows.pop(flow.reverse_flow_id())

    def _timeout_process(self, flow, packet):
        """
        The encapsulation of the process of timeout packets.

        Parameters
        ----------
        flow: Flow
            Currently processing flow.
        packet: BasicPacket
            The timeout packet.
        """
        self.logger.debug(f'Flow Timeout: {flow.flow_id}')
        if flow.packet_count > 1:
            self.finished_flows.append(flow)
        if flow.flow_id in self.current_flows:
            self.current_flows.pop(flow.flow_id)
        self.current_flows[flow.flow_id] = Flow(packet, self.flow_timeout)

    def dumpflows_to_csv(self, output_file):
        """
        Dump the statistics of all flows in `finished_flow` and generate target CSV file.

        If there are remaining flows in `current_flows`, move them to `finished_flows`.

        Parameters
        ----------
        output_file: str
            The file name of output file.
        """
        header = [
            "Flow ID",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "Protocol",
            "Start Time",
            "End Time",
            "Start Timestamp",
            "End Timestamp",
            "Flow Duration",

            "Total Packet Length",
            "Min Packet Length",
            "Max Packet Length",
            "Mean Packet Length",
            "Std Packet Length",

            "Total Fwd Packet Length",
            "Min Fwd Packet Length",
            "Max Fwd Packet Length",
            "Mean Fwd Packet Length",
            "Std Fwd Packet Length",

            "Total Bwd Packet Length",
            "Min Bwd Packet Length",
            "Max Bwd Packet Length",
            "Mean Bwd Packet Length",
            "Std Bwd Packet Length",

            "Total Fwd Header Length",
            "Min Fwd Header Length",
            "Max Fwd Header Length",
            "Mean Fwd Header Length",
            "Std Fwd Header Length",

            "Total Bwd Header Length",
            "Min Bwd Header Length",
            "Max Bwd Header Length",
            "Mean Bwd Header Length",
            "Std Bwd Header Length",

            "Total Fwd Payload Length",
            "Min Fwd Payload Length",
            "Max Fwd Payload Length",
            "Mean Fwd Payload Length",
            "Std Fwd Payload Length",

            "Total Bwd Payload Length",
            "Min Bwd Payload Length",
            "Max Bwd Payload Length",
            "Mean Bwd Payload Length",
            "Std Bwd Payload Length",

            "Packet Count",
            "Fwd Packet Count",
            "Bwd Packet Count",

            "Packet Rate",
            "Fwd Packet Rate",
            "Bwd Packet Rate",

            "Bytes Rate",
            "Fwd Bytes Rate",
            "Bwd Bytes Rate",

            "SYN Count",
            "ACK Count",
            "RST Count",
            "URG Count",
            "PSH Count",
            "FIN Count",

            "Init Window Size",

            "Min Packet Interval",
            "Max Packet Interval",
            "Mean Packet Interval",
            "Std Packet Interval",

            "Min Fwd Packet Interval",
            "Max Fwd Packet Interval",
            "Mean Fwd Packet Interval",
            "Std Fwd Packet Interval",

            "Min Bwd Packet Interval",
            "Max Bwd Packet Interval",
            "Mean Bwd Packet Interval",
            "Std Bwd Packet Interval",
        ]
        lines = [','.join(header) + '\n']
        # FIXME: Currently the last packet in an incomplete flow will invoke a dead loop.
        while self.current_flows:
            flow_id = list(self.current_flows.keys())[0]
            self._move_flow_from_current_to_finished(self.current_flows[flow_id])
        for flow in tqdm(self.finished_flows, total=len(self.finished_flows)):
            data_line = [
                flow.flow_id,
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                flow.protocol,
                flow.start_time,
                flow.end_time,
                flow.start_timestamp,
                flow.end_timestamp,
                flow.flow_duration,

                flow.total_packet_length,
                flow.min_packet_length,
                flow.max_packet_length,
                flow.mean_packet_length,
                flow.std_packet_length,

                flow.total_forward_packet_length,
                flow.min_forward_packet_length,
                flow.max_forward_packet_length,
                flow.mean_forward_packet_length,
                flow.std_forward_packet_length,

                flow.total_backward_packet_length,
                flow.min_backward_packet_length,
                flow.max_backward_packet_length,
                flow.mean_backward_packet_length,
                flow.std_backward_packet_length,

                flow.total_forward_packet_header_length,
                flow.min_forward_packet_header_length,
                flow.max_forward_packet_header_length,
                flow.mean_forward_packet_header_length,
                flow.std_forward_packet_header_length,

                flow.total_backward_packet_header_length,
                flow.min_backward_packet_header_length,
                flow.max_backward_packet_header_length,
                flow.mean_backward_packet_header_length,
                flow.std_backward_packet_header_length,

                flow.total_forward_packet_header_length,
                flow.min_forward_packet_payload_length,
                flow.max_forward_packet_payload_length,
                flow.mean_forward_packet_payload_length,
                flow.std_forward_packet_payload_length,

                flow.total_backward_packet_payload_length,
                flow.min_backward_packet_payload_length,
                flow.max_backward_packet_payload_length,
                flow.mean_backward_packet_payload_length,
                flow.std_backward_packet_payload_length,

                flow.packet_count,
                flow.forward_packet_count,
                flow.backward_packet_count,

                flow.packet_rate,
                flow.forward_packet_rate,
                flow.backward_packet_rate,

                flow.bytes_rate,
                flow.forward_bytes_rate,
                flow.backward_bytes_rate,

                flow.tcp_flags[0],
                flow.tcp_flags[1],
                flow.tcp_flags[2],
                flow.tcp_flags[3],
                flow.tcp_flags[4],
                flow.tcp_flags[5],

                flow.init_window_size,

                flow.min_packet_interval,
                flow.max_packet_interval,
                flow.mean_packet_interval,
                flow.std_packet_interval,

                flow.min_forward_packet_interval,
                flow.max_forward_packet_interval,
                flow.mean_forward_packet_interval,
                flow.std_forward_packet_interval,

                flow.min_backward_packet_interval,
                flow.max_backward_packet_interval,
                flow.mean_backward_packet_interval,
                flow.std_backward_packet_interval,
            ]
            data_line = list(map(str, data_line))
            data_str = ','.join(data_line) + '\n'
            lines.append(data_str)
        try:
            of = open(output_file, 'w+')
            of.writelines(lines)
            self.logger.info(f'Create output file {output_file} successfully.')
            of.close()
        except FileNotFoundError:
            self.logger.error(f'Create output file {output_file} failed!', exc_info=True)
