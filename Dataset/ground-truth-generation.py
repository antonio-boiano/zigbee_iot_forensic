#0x65e5f se è un on off or un report attribute generato da noi

import os
import pandas as pd
import pyshark


# Device mappings
device_type_mapping_v1 = {
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

device_name_mapping_v1 = {
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


device_type_mapping_v2 = {
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

device_name_mapping_v2 = {
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


def main(input_file):
    """
    Process a .pcapng file using pyshark, map packets to rows,
    focusing on `src_address` to `Device Name Label`.
    Returns a DataFrame.
    """
    packets = pyshark.FileCapture(input_file)  # Example filter for Zigbee
    rows = []

    for packet in packets:
        try:
            # Extract source address
            source_addr = packet.wpan.src16 if hasattr(packet.wpan, 'src16') else None
            
            # Map source address to Device Name and Device Type with fallback
            device_name = (
                device_name_mapping_v1.get(source_addr) 
                or device_name_mapping_v2.get(source_addr, 'Unknown')
            )

            device_type = (
                device_type_mapping_v2.get(source_addr) 
                or device_type_mapping_v2.get(source_addr, 'Unknown')
            )
            
            
            
            # Append row
            rows.append({
                'Packet Number': packet.number,
                'Device Name': device_name,  # Direct mapping of src_address to device name
                'Device Type': device_type,  # Direct mapping of src_address to device type
            })

        except AttributeError as e:
            print(f"Packet skipped due to missing attributes: {e}")

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
    
    
root_path = './Data'

find_and_process_pcapng(root_path)
