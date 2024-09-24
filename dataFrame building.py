## Create the dataframe starting from the pcap files inside the folder specified in dir_path

import os
import pyshark
import pandas as pd
VERSION = 2

dir_path = f"/home/antonio/Desktop/FL IoT Forensics/Niccol-/acquisition_v{VERSION}/useful"
dict_list = list()

for file in os.listdir(dir_path):
    print(file)
    pcap = pyshark.FileCapture(os.path.join(dir_path, file))

    for packet in pcap:
        packet_time = packet.frame_info.time
        if("v4" in dir_path and 
           file == 'physicalInteraction1.pcapng' and packet.number == '2126' or
           file == 'physicalInteraction2.pcapng' and packet.number == '1556' or
           file == 'idle2.pcapng' and packet.number == '17066'):
            continue
        if("v2" in dir_path and
           file == 'physicalInteraction1.pcapng' and packet.number == '2502'):
            continue
        if "000 ora legale Europa occidentale" in packet.frame_info.time:
            packet_time = packet.frame_info.time.replace("000 ora legale Europa occidentale", "")
        elif "000 ora solare Europa occidentale" in packet.frame_info.time:
            packet_time = packet.frame_info.time.replace("000 ora solare Europa occidentale", "")
        packet_length = packet.frame_info.len
        
        number_of_layers = len(packet.layers)
        
        packet_delta_time = None
        packet_sequence_number = None
        packet_source_ieee = None
        packet_destination_ieee = None
        ieee_frame_control_field = None
        packet_source_zigbee = None
        packet_destination_zigbee = None
        extended_packet_source = None
        packet_payload_length = None
        zigbee_frame_control_field = None

        #IEEE 802.15.4 packet
        if number_of_layers == 1:
            try:
                packet_delta_time = packet.frame_info.time_delta[:-3]
                packet_sequence_number = packet['WPAN'].seq_no
                ieee_frame_control_field = packet['WPAN'].fcf
                packet_source_ieee = packet['WPAN'].src16
                packet_destination_ieee = packet['WPAN'].dst16
            except AttributeError:
                pass
                
        #Zigbee packet
        elif number_of_layers == 2:
            try:
                packet_delta_time = packet.frame_info.time_delta[:-3]
                packet_sequence_number = packet['WPAN'].seq_no
                ieee_frame_control_field = packet['WPAN'].fcf
                packet_source_ieee = packet['WPAN'].src16
                packet_destination_ieee = packet['WPAN'].dst16
                zigbee_frame_control_field = packet['ZBEE_NWK'].fcf
                packet_source_zigbee = packet['ZBEE_NWK'].src
                packet_destination_zigbee = packet['ZBEE_NWK'].dst
                extended_packet_source = packet['ZBEE_NWK'].zbee_sec_src64
                packet_payload_length = packet['ZBEE_NWK'].data_len
            except AttributeError:
                pass
            #Packet with bad FCS, Unkonwn command
            except KeyError:
                pass
        
        if("v4" in dir_path):
            if(file == 'physicalInteraction1.pcapng' and packet.number == '2127'):
                packet_delta_time = '0.005102000'
            if(file == 'physicalInteraction2.pcapng' and packet.number == '1557'):
                packet_delta_time = '0.006017000'
            if(file == 'idle2.pcapng' and packet.number == '17067'):
                packet_delta_time = '2.690662000'
        if("v2" in dir_path):
            if(file == 'physicalInteraction1.pcapng' and packet.number == '2503'):
                packet_delta_time = '0.008997000'

        dict_list.append({'Time': packet_time,
                        'Delta Time': packet_delta_time, 
                        'Length': packet_length, 
                        'Source IEEE': packet_source_ieee, 
                        'Destination IEEE': packet_destination_ieee, 
                        'FCF IEEE': ieee_frame_control_field,
                        'Sequence Number': packet_sequence_number,
                        'Source Zigbee': packet_source_zigbee, 
                        'Destination Zigbee': packet_destination_zigbee, 
                        'FCF Zigbee': zigbee_frame_control_field, 
                        'Payload Length': packet_payload_length,
                        'Extended Source': extended_packet_source,
                        'File': file})

dataFrame = pd.DataFrame(dict_list)
dataFrame.to_csv(f'final_dataFrame_v{VERSION}_anto.csv')
