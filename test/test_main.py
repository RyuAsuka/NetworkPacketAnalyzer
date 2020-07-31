from scapy.all import *
from tqdm import tqdm


FLOW_TIMEOUT = 120000000
ACTIVITY_TIMEOUT = 5000000


def print_help():
    print(
        """
        Usage:
            NetworkPacketAnalyzer <input_file> <output_file>
        """
    )


class Cmd(object):
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.flow_generator = FlowGenerator(flow_timeout=FLOW_TIMEOUT, flow_activity_timeout=ACTIVITY_TIMEOUT)
        self.id_generator = IdGenerator()

    def run(self):
        n_valid = 0
        n_discard = 0
        pcap_file = rdpcap(self.input_file)
        total_packets = len(pcap_file)
        for cap_packet in tqdm(pcap_file, total=total_packets):
            timestamp = int(cap_packet.time * 1000000)
            if 'IP' in cap_packet:
                ip_packet = cap_packet['IP']
                basic_packet = BasicPacketInfo(self.id_generator, timestamp, ip_packet)
                self.flow_generator.add_packet(basic_packet)
                n_valid += 1
            else:
                n_discard += 1
        self.flow_generator.dump_all_flows(self.output_file)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print_help()
    cmd = Cmd(sys.argv[1], sys.argv[2])
    cmd.run()
