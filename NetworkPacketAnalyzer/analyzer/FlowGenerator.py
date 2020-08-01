from tqdm import tqdm
from NetworkPacketAnalyzer.entities.Flow import Flow
from NetworkPacketAnalyzer.entities.BasicPacket import BasicPacket
from NetworkPacketAnalyzer.utils.logger import MyLogger
from NetworkPacketAnalyzer.utils.FlowStatus import FlowStatus


class FlowGenerator(object):
    """
    维护两个存储空间，分别表示当前正在处理的流 `current_flows` 和
    已经处理完毕的流 `finished_flows`。

    当一个流符合结束条件时，`current_flows` 中的该流会被加入到 `finished_flows` 中。

    Notes
    -----
    流的结束条件：

        1. 流中含有 FIN 报文。当四次握手结束后，该流视为结束。（仅限TCP流）
        2. 流中含有 RST 报文。一旦出现 RST 报文，则该流视为结束。（仅限TCP流）
        3. 下一个符合流 ID 的报文到达时，已经超过了超时时间。（适用于 TCP 流和 UDP 流）

    Attributes
    ----------
    current_flows: dict of {str: Flow}
        当前正在处理的流。
    finished_flows: list of Flow
        被视为结束的流。
    flow_timeout: int
        流超时时间。

    Parameters
    ----------
    flow_timeout: int
        流超时时间。

    """
    def __init__(self, flow_timeout):
        self.current_flows = {}
        self.finished_flows = []
        self.flow_timeout = flow_timeout
        self.logger = MyLogger('FlowGenerator')

    def add_packet(self, packet):
        """
        向流生成器中添加数据包。

        Parameters
        ----------
        packet: BasicPacket
            经过处理的 BasicPacket 数据包对象。
        """
        if not packet:
            return
        forward_packet_flow_id = packet.forward_flow_id()
        backward_packet_flow_id = packet.backward_flow_id()
        current_timestamp = packet.timestamp
        if forward_packet_flow_id not in self.current_flows and backward_packet_flow_id not in self.current_flows:
            # 说明是一个新的流的开始
            self.current_flows[forward_packet_flow_id] = Flow(packet, self.flow_timeout)
        else:
            if forward_packet_flow_id in self.current_flows:
                flow = self.current_flows[forward_packet_flow_id]
            else:
                flow = self.current_flows[backward_packet_flow_id]

            # 流活跃状态下：
            # 1. 当收到一个包发现其超时后，结束当前流并生成一个新的流。
            # 2. 收到前向 FIN 报文，进入 FIN_WAIT_1 状态。
            # 3. 收到后向 FIN 报文，进入 CLOSE_WAIT 状态。
            # 4. 收到普通报文，将其添加入所属的流中。
            if flow.flow_status == FlowStatus.ACTIVE:
                # 流超时的情况
                # 将当前流从 current_flows 中移动到 finished_flows
                # 将该数据包组成一个新的流
                if current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)
                # 接收到 FIN 报文的情况
                # 若是前向 FIN（从客户端发起的 FIN），则进入 FIN_WAIT_1 状态
                # 若是后向 FIN（从服务端发起的 FIN），则进入 CLOSE_WAIT 状态
                elif packet.hasFIN:
                    flow.add_packet(packet)
                    if packet.forward_flow_id() == flow.flow_id:
                        flow.flow_status = FlowStatus.FIN_WAIT_1
                    else:
                        flow.flow_status = FlowStatus.CLOSE_WAIT
                # 接收到 RST 的情况
                # 将当前流移动到 finished_flows
                # 并将该流从当前流中删除
                elif packet.hasRST:
                    self.logger.debug(f'Received a RST packet: {flow.flow_id}')
                    flow.add_packet(packet)
                    self._move_flow_from_current_to_finished(flow)
                # 其他情况：向该流中正常添加数据包。
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
                elif current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.CLOSING:
                flow.add_packet(packet)
                if packet.hasACK:
                    self._move_flow_from_current_to_finished(flow)
                elif current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.CLOSE_WAIT:
                flow.add_packet(packet)
                if packet.backward_flow_id() == flow.flow_id and packet.hasFIN:
                    flow.flow_status = FlowStatus.LAST_ACK
                elif current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.LAST_ACK:
                flow.add_packet(packet)
                if packet.hasACK:
                    self._move_flow_from_current_to_finished(flow)
                elif current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)
            elif flow.flow_status == FlowStatus.TIME_WAIT:
                if current_timestamp - flow.start_time > self.flow_timeout:
                    self._timeout_process(flow, packet)

    def _move_flow_from_current_to_finished(self, flow):
        """
        将流从当前流 current_flow 中移动到结束流 finished_flow.

        Parameters
        ----------
        flow: Flow
            要移动的流。
        """
        self.finished_flows.append(flow)
        self.current_flows.pop(flow.flow_id)

    def _timeout_process(self, flow, packet):
        """
        对超时处理的封装。

        Parameters
        ----------
        flow: Flow
            当前正在处理的流。
        packet: BasicPacket
            对超时的流，当前到达的数据包要重新建一个新的流。
        """
        self.logger.debug(f'Flow Timeout: {flow.flow_id}')
        if flow.packet_count > 1:
            self.finished_flows.append(flow)
        self.current_flows.pop(flow.flow_id)
        self.current_flows[flow.flow_id] = Flow(packet, self.flow_timeout)

    def dumpflows_to_csv(self, output_file):
        """
        若 current_flows 还有未处理的流，则将他们加入 finished_flows。
        然后将 finished_flows 中的所有流写入由 output_file 指定的 csv 文件中。

        Parameters
        ----------
        output_file: str
            指定输出文件的文件名。
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
            with open(output_file, 'w+') as of:
                of.writelines(lines)
                self.logger.info(f'Create output file {output_file} successfully.')
        except Exception:
            self.logger.error(f'Create output file {output_file} failed!', exc_info=True)
