# This script is used to generate the ground truth of the events

import os
import pyshark
import pandas as pd

dir_path = r"C:\Users\User\Documents\Niccolò\PoliMi\Tesi\acquisition_v4\useful\androidAppInteraction1.pcapng"
ground_truth = list()

def isLinkStatus(packet):
    return packet['WPAN'].fcf == '0x8841'

def isAck(packet):
    return packet['WPAN'].fcf == '0x0002'

command_attributes = [
    'zbee_zcl.cmd.id',
    'zbee_zcl_lighting.color_control.cmd.srv_rx.id',
    'zbee_zcl_general.groups.cmd_srv_rx.id',
    'zbee_zcl_general.groups.cmd.srv_tx.id',
    'zbee_zcl_general.level_control.cmd.srv_rx.id',
    'zbee_zcl_general.onoff.cmd.srv_rx.id',
    'zbee_nwk.cmd.id',
    'zbee_zcl_ias.zone.cmd.srv_tx.id'
]

tot_packets = 0

for file in os.listdir(dir_path):
    print(file)
    pcap = pyshark.FileCapture(os.path.join(dir_path, file))
    packets_count = 0
    try:
        for packet in pcap:
            if("v4" in dir_path and 
            file == 'physicalInteraction1.pcapng' and packet.number == '2126' or
            file == 'physicalInteraction2.pcapng' and packet.number == '1556' or
            file == 'idle2.pcapng' and packet.number == '17066'):
                continue
            if("v2" in dir_path and
            file == 'physicalInteraction1.pcapng' and packet.number == '2502'):
                continue

            packet_command = ''
            zcl_inserted = False
            nwk_inserted = False

            if 'ZBEE_BEACON' in packet:
                ground_truth.append('beacon')
                packets_count += 1
                tot_packets += 1
                continue
            if 'ZBEE_ZDP' in packet:
                ground_truth.append('zdp')
                packets_count += 1
                tot_packets += 1
                continue
            if 'ZBEE_ZCL' in packet:
                for attribute in packet['ZBEE_ZCL']._all_fields.values():
                    if attribute.name in command_attributes:
                        packet_command = attribute.showname_value
                        ground_truth.append(packet_command)
                        packets_count += 1
                        tot_packets += 1
                        zcl_inserted = True
                        continue 
            if 'ZBEE_APS' in packet and not zcl_inserted:
                ground_truth.append('APS: Ack')
                packets_count += 1
                tot_packets += 1
                continue
            if isLinkStatus(packet) and not zcl_inserted:
                ground_truth.append('Link Status')
                packets_count += 1
                tot_packets += 1
                continue
            if isAck(packet):
                ground_truth.append('Ack')
                packets_count += 1
                tot_packets += 1
                continue
            if not zcl_inserted:
                if 'ZBEE_NWK' in packet:
                    for attribute in packet['ZBEE_NWK']._all_fields.values():
                        if attribute.name in command_attributes:
                            packet_command = attribute.showname_value
                            ground_truth.append(packet_command)
                            packets_count += 1
                            tot_packets += 1
                            nwk_inserted = True
                            continue
                if not nwk_inserted:
                    ground_truth.append('---')
                    packets_count += 1
                    tot_packets += 1
        print(packets_count)
    finally:
        pcap.close()

print(tot_packets)
dataFrame = pd.DataFrame(ground_truth)
dataFrame.to_csv('ground_truth_v2.csv')