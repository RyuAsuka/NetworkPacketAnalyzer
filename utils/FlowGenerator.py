from Entities.BasicPacketInfo import BasicPacketInfo
from Entities.BasicFlow import BasicFlow
from Entities.BasicPacketInfo import FlowDirection


class FlowGenerator(object):
    """
    流生成器。维护两个字典，分别是记录当前流的 current_flows 和
    记录已结束的流的 finished_flows。

    Parameters
    ----------
    flow_timeout: int
        指示流超时时间。
    flow_activity_timeout: int
        指示流活跃超时时间。

    Attributes
    ----------
    finished_flow_count: int
        已结束的流的个数。
    current_flows: dict[str, BasicFlow]
        存放目前正在处理的流。
    finished_flows: dict[int, BasicFlow]
        存放已经被标记为结束的流。
    is_bidirectional: boolean
        表示该流是否为双向流。
    flow_timeout: int
        指示流超时时间。
    flow_activity_timeout: int
        指示流活跃超时时间。
    """
    def __init__(self, flow_timeout, flow_activity_timeout):
        self.finished_flow_count = 0
        self.current_flows = {}
        self.finished_flows = {}
        self.is_bidirectional = False
        self.flow_timeout = flow_timeout
        self.flow_activity_timeout = flow_activity_timeout

    def add_packet(self, packet):
        """
        向当前流中添加包。

        Parameters
        ----------
        packet: BasicPacketInfo
            准备添加的数据包。
        """
        if not packet:
            return

        current_timestamp = packet.timestamp
        temp_id_fwd = packet.generate_flow_id(FlowDirection.FORWARD)
        temp_id_bwd = packet.generate_flow_id(FlowDirection.BACKWARD)
        if temp_id_fwd in self.current_flows.keys() or temp_id_bwd in self.current_flows.keys():
            if temp_id_fwd in self.current_flows.keys():
                current_flow_id = temp_id_fwd
            else:
                current_flow_id = temp_id_bwd

            flow = self.current_flows[current_flow_id]
            flow: BasicFlow
            if current_timestamp - flow.flow_start_time > self.flow_timeout:
                if flow.packet_count() > 1:
                    self.finished_flows[self.get_flow_count()] = flow
                self.current_flows.pop(current_flow_id)
                self.current_flows[current_flow_id] = BasicFlow(
                    self.is_bidirectional,
                    packet,
                    flow.src,
                    flow.dst,
                    flow.src_port,
                    flow.dst_port,
                    self.flow_activity_timeout
                )
                current_flow_size = len(self.current_flows)
                # output log
                # if current_flow_size % 50 == 0:
                #     logger.debug(f"Timeout: Current has {current_flow_size} flow.")
            elif packet.flagFIN:
                # logger.debug(f"FlagFIN: Current has {len(self.current_flows)} flow.")
                flow.add_packet(packet)
                self.finished_flows[self.get_flow_count()] = flow
                self.current_flows.pop(current_flow_id)
            else:
                flow.update_active_idle_time(current_timestamp, self.flow_activity_timeout)
                flow.add_packet(packet)
                self.current_flows[current_flow_id] = flow
        else:
            self.current_flows[temp_id_fwd] = BasicFlow(
                self.is_bidirectional,
                packet,
                activity_timeout=self.flow_activity_timeout
            )

    def get_flow_count(self):
        self.finished_flow_count += 1
        return self.finished_flow_count

    # TODO: Implement function dump_all_flows
    def dump_all_flows(self, output_file):
        pass
