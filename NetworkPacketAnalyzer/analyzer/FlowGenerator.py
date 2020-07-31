from NetworkPacketAnalyzer.entities.Flow import Flow
from NetworkPacketAnalyzer.entities.BasicPacket import BasicPacket


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
    current_flows: dict[str, Flow]
        当前正在处理的流。
    finished_flows: list[Flow]
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

    # TODO: 实现 add_packet 方法
    def add_packet(self, packet):
        """
        向流生成器中添加数据包。

        Parameters
        ----------
        packet: BasicPacket
            经过处理的 BasicPacket 数据包对象。
        """
        pass

    # TODO: 实现 dumpflows_to_csv 方法
    def dumpflows_to_csv(self, output_file):
        """
        若 current_flows 还有未处理的流，则将他们加入 finished_flows。
        然后将 finished_flows 中的所有流写入由 output_file 指定的 csv 文件中。

        Parameters
        ----------
        output_file: str
            指定输出文件的文件名。
        """
        pass
