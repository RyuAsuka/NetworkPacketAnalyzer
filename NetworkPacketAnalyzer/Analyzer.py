"""
The main programme.

Usage
-----
    Analyzer `input_file` `output_file`

Examples
--------
    Analyzer "data/captured.pcap" "data/captured.csv"
"""


from scapy.all import *
from pcapfile.savefile import load_savefile
from tqdm import tqdm
from analyzer.FlowGenerator import FlowGenerator
from utils.logger import MyLogger
from entities.BasicPacket import BasicPacket
from utils.NotifierWin32 import NotifierWin32
try:
    from utils.NotifierLinux import NotifierLinux
except ImportError:
    pass


FLOW_TIMEOUT = 120000000  # 120 seconds
APP_NAME = 'NetworkPacketAnalyzer'


if __name__ == '__main__':
    logger = MyLogger('main')

    if len(sys.argv) != 3:
        logger.error('Argument insufficient. Need Inputfile and Outputfile')
        exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Set notifier
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
    start_time = time.time()
    reader = load_savefile(open(input_file, 'rb'))
    total_num_packets = len(reader.packets)
    reader = PcapReader(input_file)
    end_time = time.time()
    logger.info(f'Done! Time elapsed: {(end_time - start_time):.2f}s')
    logger.info('Start reading packets...')
    pbar = tqdm(total=total_num_packets, unit='bytes')
    processed_packets = 0
    while True:
        try:
            pkt = reader.next()
            processed_packets += 1
            pkt_size = len(pkt)
            pbar.update(1)
            timestamp = pkt.time * 1000000
            if 'IP' in pkt:
                try:
                    ip_packet = pkt['IP']
                    basic_packet = BasicPacket(processed_packets, timestamp, ip_packet)
                    flow_generator.add_packet(basic_packet)
                    n_valid += 1
                except TypeError:
                    logger.error('TypeError: Current packet ID = %d', total_num_packets)
                    logger.error('packet: %s', repr(pkt['IP']), exc_info=1)
            else:
                n_discard += 1
        except StopIteration:
            break
    notifier.send_notification(APP_NAME, "Packet analyzing complete!")

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
