from scapy.all import *
from tqdm import tqdm
from NetworkPacketAnalyzer.analyzer.FlowGenerator import FlowGenerator
from NetworkPacketAnalyzer.utils.logger import MyLogger
from NetworkPacketAnalyzer.entities.BasicPacket import BasicPacket


FLOW_TIMEOUT = 120000000  # 120 seconds


if __name__ == '__main__':
    logger = MyLogger('main')
    if len(sys.argv) != 3:
        logger.error('Argument insufficient. Need Inputfile and Outputfile')
        exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    flow_generator = FlowGenerator(flow_timeout=FLOW_TIMEOUT)
    n_valid = 0
    n_discard = 0
    all_packets = rdpcap(input_file)
    total_num_packets = len(all_packets)
    logger.info("Start reading packets...")
    for packet_id, single_packet in tqdm(enumerate(all_packets), total=total_num_packets):
        timestamp = int(single_packet.time * 1000000)  # microseconds
        if 'IP' in single_packet:
            ip_packet = single_packet['IP']  # only analyze IPv4 packets. IPv6 packets will be discarded.
            basic_packet = BasicPacket(packet_id, timestamp, ip_packet)
            flow_generator.add_packet(basic_packet)
            n_valid += 1
        else:
            n_discard -= 1
    logger.info(f"End reading packets.\nTotal {all_packets} packets.\n{n_valid} is valid.\n{n_discard} is discarded.")
    logger.info(f'Write into file: {output_file}')
    try:
        flow_generator.dumpflows_to_csv(output_file)
        logger.info('Done!')
    except FileNotFoundError as e:
        logger.error(f"{output_file} does not exist.", exc_info=True)
