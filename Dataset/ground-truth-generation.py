#0x65e5f se è un on off or un report attribute generato da noi

import os
import pandas as pd
import pyshark
import re


# Device mappings
device_type_mapping_vA = {
    '0x0000': 'Coordinator',
    '0x09ac': 'Socket',
    '0x5db6': 'Door',
    '0xe694': 'Socket',
    '0x772c': 'Door',
    '0x61af': 'Vibration',
    '0xe011': 'Button',
    '0x9989': 'Motion',
    '0x265e': 'Temperature',
    '0xb815': 'Motion',
    '0x4e52': 'Motion',
    '0x3181': 'Door',
    '0x0a79': 'Door',
    '0x82eb': 'Socket',
    '0x6e5f': 'Socket',
    '0xc8f0': 'Socket',
    '0xebe5': 'Bulb',
    '0x054f': 'Bulb',
    '0x482d': 'Bulb',
    '0xa209': 'Bulb',
    '0x2cae': 'Motion',
    '0xe5c4': 'Bulb',
}

device_name_mapping_vA = {
    '0x0000': 'Coordinator',
    '0x09ac': 'Ledvance Z3 Plug',
    '0x5db6': 'Aqara Door 1',
    '0xe694': 'Smart Socket',
    '0x772c': 'Aqara Door 2',
    '0x61af': 'Aqara Vibration',
    '0xe011': 'Aqara Button',
    '0x9989': 'Aqara Motion',
    '0x265e': 'Sonoff Temperature',
    '0xb815': 'Sonoff Motion 1',
    '0x4e52': 'Sonoff Motion 2',
    '0x3181': 'Sonoff Door 1',
    '0x0a79': 'Sonoff Door 2',
    '0x82eb': 'Ledvance Smart+ Plug',
    '0x6e5f': 'Power Plug 1',
    '0xc8f0': 'Power Plug 2',
    '0xebe5': 'Moes Bulb',
    '0x054f': 'Ledvance Bulb',
    '0x482d': 'Philips Lamp 1',
    '0xa209': 'Philips Lamp 2',
    '0x2cae': 'Philips Lamp 3',
    '0xe5c4': 'Philips Motion',
}


device_type_mapping_vB = {
    '0x0000': 'Coordinator',
    '0x4615': 'Temperature',
    '0x946e': 'Door',
    '0x7b10': 'Door',
    '0xd0bb': 'Motion',
    '0x1f29': 'Motion',
    '0x27d7': 'Motion',
    '0x907b': 'Door',
    '0xe01d': 'Door',
    '0x187a': 'Vibration',
    '0xc31c': 'Button',
    '0xe1a6': 'Socket',
    '0x3d95': 'Socket',
    '0xa706': 'Socket',
    '0x4e11': 'Socket',
    '0x0112': 'Socket',
    '0xec7f': 'Bulb',
    '0x1e15': 'Bulb',
    '0x1cd8': 'Bulb',
    '0x5bb9': 'Bulb',
    '0x711c': 'Bulb',
    '0x059b': 'Motion'    
}

device_name_mapping_vB = {
    '0x0000': 'Coordinator',
    '0x4615': 'Sonoff Temperature',
    '0x946e': 'Sonoff Door 1',
    '0x7b10': 'Sonoff Door 2',
    '0xd0bb': 'Sonoff Motion 1',
    '0x1f29': 'Sonoff Motion 2',
    '0x27d7': 'Aqara Motion',
    '0x907b': 'Aqara Door 1',
    '0xe01d': 'Aqara Door 2',
    '0x187a': 'Aqara Vibration',
    '0xc31c': 'Aqara Button',
    '0xe1a6': 'Smart Socket',
    '0x3d95': 'Power Plug 1',
    '0xa706': 'Power Plug 2',
    '0x4e11': 'Ledvance Z3 Plug',
    '0x0112': 'Ledvance Smart+ Plug',
    '0xec7f': 'Ledvance Bulb',
    '0x1e15': 'Moes Bulb',
    '0x1cd8': 'Philips Lamp 1',
    '0x5bb9': 'Philips Lamp 2',
    '0x711c': 'Philips Lamp 3',
    '0x059b': 'Philips Motion' 
}


def parse_layer_data(input_string):
    """
    Parses the given input string into a structured dictionary.
    
    Args:
        input_string (str): The formatted string to parse.

    Returns:
        dict: A nested dictionary representing the parsed data.
    """
    import re

    # Split the input string into lines, ensuring consistency in handling newline characters
    lines = input_string.replace('\r\n', '\n').replace('\r', '\n').split('\n')

    # Initialize a dictionary to store the parsed data
    parsed_data = {}
    current_key = None

    # Regular expressions for parsing
    key_value_pattern = re.compile(r"^(\w[\w\s]+):\s*(.*)")
    subkey_value_pattern = re.compile(r"^\t(.*?):\s*(.*)")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Match top-level keys
        key_match = key_value_pattern.match(line)
        if key_match:
            current_key = key_match.group(1)
            if current_key in parsed_data:
                if isinstance(parsed_data[current_key], list):
                    parsed_data[current_key].append(key_match.group(2))
                else:
                    parsed_data[current_key] = [parsed_data[current_key], key_match.group(2)]
            else:
                parsed_data[current_key] = key_match.group(2)
            continue

        # Match subkeys under the current key
        if current_key:
            subkey_match = subkey_value_pattern.match(line)
            if subkey_match:
                subkey = subkey_match.group(1)
                value = subkey_match.group(2)
                if not isinstance(parsed_data[current_key], dict):
                    parsed_data[current_key] = {}
                parsed_data[current_key][subkey] = value

    return parsed_data


def detect_cmd(src_addr, packet,dict_mem = {},device_name = None):  
    """
    Detects the human-readable command string based on the source address and command ID.
    Args:
        src_addr (str): The source address of the packet.
        packet (pyshark.packet.packet.Packet): The pyshark packet to classify.
    
    Returns:
        int: 1 if the command is human-readable, 0 otherwise.
    """
    
    human_cmd = [
        'zbee_zcl_lighting.color_control.cmd.srv_rx.id',
        'zbee_zcl_general.level_control.cmd.srv_rx.id',
        'zbee_zcl_general.onoff.cmd.srv_rx.id',
        'zbee_zcl_ias.zone.cmd.srv_tx.id'
    ]
    
    
    
    if 'ZBEE_ZCL' in packet:
        for attribute in packet['ZBEE_ZCL']._all_fields.values():
            if attribute.name in human_cmd:
                return 1
            
    cmd_id = None
    cmd_str = None
    
    if src_addr is not None and src_addr != '0x0000':
        if 'ZBEE_ZCL' in packet:
            if hasattr(packet['ZBEE_ZCL'],'cmd_id'):
                cmd_id = packet['ZBEE_ZCL'].cmd_id
                cmd_str = str(packet['ZBEE_ZCL'])
                
        if cmd_id is not None and cmd_str is not None:
            if cmd_id == '0x0a' and hasattr(packet['ZBEE_ZCL'], 'zbee_zcl_general_onoff_attr_onoff'):
                if src_addr in dict_mem:
                    if dict_mem[src_addr] != packet['ZBEE_ZCL'].zbee_zcl_general_onoff_attr_onoff:
                        dict_mem[src_addr] = packet['ZBEE_ZCL'].zbee_zcl_general_onoff_attr_onoff
                        return 1
                else:
                    dict_mem[src_addr] = packet['ZBEE_ZCL'].zbee_zcl_general_onoff_attr_onoff
            
            if cmd_id == '0x0a' and device_name is not None and (device_name == 'Aqara Button' or device_name == 'Aqara Vibration'):
                try: 
                    if packet['ZBEE_ZCL'].attr_id == '0xff01':
                        return 0
                    else:
                        return 1
                except:
                    return 1
                
            if cmd_id == '0x0a' and device_name is not None and device_name == 'Aqara Motion':
                        if packet['ZBEE_ZCL'].attr_id != '0x00f7':
                            return 1
                
                   
    return 0


def classify_packet(packet):
    """
    Classify a given pyshark packet and return a label.

    Parameters:
        packet (pyshark.packet.packet.Packet): The pyshark packet to classify.

    Returns:
        str: The label for the packet.
    """
    # Define command attributes to check
    command_attributes = [
        'zbee_zcl.cmd.id',
        'zbee_zcl_lighting.color_control.cmd.srv_rx.id',
        'zbee_zcl_general.groups.cmd_srv_rx.id',
        'zbee_zcl_general.groups.cmd.srv_tx.id',
        'zbee_zcl_general.level_control.cmd.srv_rx.id',
        'zbee_zcl_general.onoff.cmd.srv_rx.id',
        'zbee_zcl_ias.zone.cmd.srv_tx.id',
        'zbee_zcl_general_ota_cmd_srv_rx_id',
        'zbee_nwk.cmd.id'
    ]
    

    def isAck(packet):
        return hasattr(packet, 'WPAN') and packet['WPAN'].fcf == '0x0002'

    try:
        if 'ZBEE_BEACON' in packet:
            return 'beacon'

        if 'ZBEE_ZDP' in packet:
            return 'zdp'

        if 'ZBEE_ZCL' in packet:
            for attribute in packet['ZBEE_ZCL']._all_fields.values():
                if attribute.name in command_attributes:
                    return attribute.showname_value

        if 'ZBEE_APS' in packet:
            if packet['ZBEE_APS'].type == '0x02':
                return 'APS: Ack'

        if isAck(packet):
            return 'Ack'

        if 'ZBEE_NWK' in packet:
            for attribute in packet['ZBEE_NWK']._all_fields.values():
                if attribute.name in command_attributes:
                    return attribute.showname_value

    except Exception as e:
        # Handle any unexpected packet processing errors
        print(f"Error processing packet: {e}")

    # Default label if no conditions are met
    return None


def strip_ansi(input_str):
    """
    Removes ANSI escape sequences from a string.
    Args:
        input_str (str): The string containing ANSI escape sequences.
    Returns:
        str: A clean string without ANSI codes.
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', input_str)

def main(input_file):
    """
    Process a .pcapng file using pyshark, map packets to rows,
    focusing on `src_address` to `Device Name Label`.
    Returns a DataFrame.
    """

    def safe_get_attr(obj, attr, default=None):
        """Safely retrieve an attribute from an object."""
        return getattr(obj, attr, default)

    def map_device_info(source_addr, mapping):
        """Map source address to device name/type with fallback."""
        return mapping.get(source_addr, 'Unknown')
    
    def get_topology_mapping(input_file):
        """Get the device name and type mappings for the specified topology."""
        if 'Topology_A' in input_file:
            return device_name_mapping_vA, device_type_mapping_vA
        elif 'Topology_B' in input_file:
            return device_name_mapping_vB, device_type_mapping_vB
        else:
            raise ValueError(f"Invalid topology:")
            
    packets = pyshark.FileCapture(input_file)  # Example filter for Zigbee
    rows = []
    dict_mem = {}
    
    device_name_mapping,device_type_mapping = get_topology_mapping(input_file)
    
    for packet in packets:
        try:
            
            # Extract WPAN information
            source_addr = safe_get_attr(packet.wpan, 'src16')
            device_name = map_device_info(source_addr, device_name_mapping)
            device_type = map_device_info(source_addr, device_type_mapping)

            # Extract ZigBee NWK information
            source_addr_zb = None
            device_name_zb = None
            device_name_zb_dst = None
            device_type_zb = None
            human_cmd = None

            try:
                source_addr_zb = safe_get_attr(packet.ZBEE_NWK, 'src')
            except:
                pass

            try:
                device_name_zb = map_device_info(source_addr_zb, device_name_mapping)
            except:
                pass

            try:
                device_name_zb_dst = map_device_info(
                    safe_get_attr(packet.ZBEE_NWK, 'dst'),device_name_mapping
            )
            except:
                pass

            try:
                device_type_zb = map_device_info(source_addr_zb, device_type_mapping)
            except:
                pass

            try:
                human_cmd = detect_cmd(source_addr_zb, packet,dict_mem,device_name_zb)
            except:
                pass

            # Extract ZigBee ZCL information
            try:
                cmd_str = parse_layer_data(strip_ansi(str(packet.ZBEE_ZCL)))
            except:
                cmd_str = None

            # Append row
            rows.append({
                'Packet Number': packet.number,
                'Device Name': device_name,
                'Device Type': device_type,
                'Device Name ZigBee': device_name_zb,
                'Device Type ZigBee': device_type_zb,
                'Device Name ZigBee Destination': device_name_zb_dst,
                'Human Command': human_cmd,
                'Packet Type': classify_packet(packet),
                'Command String': cmd_str,
            })

        except AttributeError:
            pass  # Skip packets with missing attributes
        except:
            pass  # Catch all other unexpected errors and skip

    packets.close()

    # Convert to a DataFrame
    df = pd.DataFrame(rows)
    return df

def find_and_process_pcapng(file_path):
    """
    Search for .pcapng files, process them with main(),
    and save the result as a .csv file.
    """
    for root, dirs, files in os.walk(file_path):
        for file in files:
            if file.endswith('.pcapng'):
                full_path = os.path.join(root, file)
                
                # Create the groundtruth subfolder if it doesn't exist
                groundtruth_folder = os.path.join(root, "groundtruth")
                os.makedirs(groundtruth_folder, exist_ok=True)
                
                # Construct the output file path in the groundtruth subfolder
                output_file = os.path.join(
                    groundtruth_folder, 
                    os.path.splitext(file)[0] + '_groundtruth.csv'
                )
                
                print(f"Processing: {full_path} -> {output_file}")
                
                # Process the file
                groundtruth = main(full_path)

                # Save the df to CSV in the groundtruth subfolder
                groundtruth.to_csv(output_file, index=False)
                
    
    print("All files processed successfully.")
    
    
root_path = './Dataset/Data'

find_and_process_pcapng(root_path)
