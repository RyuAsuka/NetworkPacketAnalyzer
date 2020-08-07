"""
The main programme.

Usage
-----
    Analyzer `input_file` `output_file`

Examples
--------
    Analyzer "data/captured.pcap" "data/captured.csv"
"""


import os
from scapy.all import *
from tqdm import tqdm
from analyzer.FlowGenerator import FlowGenerator
from utils.logger import MyLogger
from entities.BasicPacket import BasicPacket
from utils.NotifierWin32 import NotifierWin32
from utils.NotifierLinux import NotifierLinux


FLOW_TIMEOUT = 120000000  # 120 seconds
APP_NAME = 'NetworkPacketAnalyzer'


if __name__ == '__main__':
    logger = MyLogger('main')
    if len(sys.argv) != 3:
        logger.error('Argument insufficient. Need Inputfile and Outputfile')
        exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    input_file_size = os.path.getsize(input_file)

    if sys.platform == 'win32':
        notifier = NotifierWin32(APP_NAME)
    elif sys.platform == 'linux':
        notifier = NotifierLinux(APP_NAME)
    else:
        notifier = None
    flow_generator = FlowGenerator(flow_timeout=FLOW_TIMEOUT)
    n_valid = 0
    n_discard = 0
    logger.info('Reading pcap file...')
    # all_packets = rdpcap(input_file)
    all_packets = PcapReader(input_file)
    logger.info('Done!')
    total_num_packets = 0
    logger.info('Start reading packets...')
    pbar = tqdm(total=input_file_size)
    while True:
        try:
            if total_num_packets % 10000 == 0:
                logger.info('%d packets are read.', total_num_packets)
            pkt = all_packets.next()
            total_num_packets += 1
            timestamp = int(pkt.time * 1000000)
            pkt_size = len(pkt)
            pbar.update(pkt_size)
            if 'IP' in pkt:
                try:
                    ip_packet = pkt['IP']
                    basic_packet = BasicPacket(total_num_packets, timestamp, pkt)
                    flow_generator.add_packet(basic_packet)
                    n_valid += 1
                except TypeError:
                    logger.error('TypeError: Current packet ID = %d', total_num_packets)
                    logger.error('packet: %s', repr(pkt['IP']), exc_info=1)
                except Exception as e:
                    logger.error('%s', e)
            else:
                n_discard += 1
        except StopIteration:
            logger.info('Done!')
            if notifier:
                notifier.send_notification(APP_NAME, "All packets processing complete!")
            break

    logger.info(
        f"End reading packets.\n"
        f"Total {total_num_packets} packets.\n"
        f"{n_valid} is valid.\n"
        f"{n_discard} is discarded."
    )
    logger.info(f'Write into file: {output_file}')
    try:
        flow_generator.dumpflows_to_csv(output_file)
        logger.info('Done!')
    except FileNotFoundError as e:
        logger.error(f"{output_file} does not exist.", exc_info=True)
