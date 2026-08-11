import xml.etree.ElementTree as ET
import sys
import os

def convert_sophos_to_fortigate(xml_file_path, output_txt_path):
    if not os.path.exists(xml_file_path):
        print(f"Error: The file '{xml_file_path}' does not exist.")
        sys.exit(1)

    try:
        # Parse Sophos XG XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        sys.exit(1)

    cli_commands = ["config firewall address"]
    object_count = 0

    # 1. Process Individual IP Host Addresses (Host Objects)
    # Sophos often nests these under <IPAddress> or <IPHost> blocks
    for ip_host in root.findall('.//IPAddress') + root.findall('.//IPHost'):
        name_node = ip_host.find('Name')
        ip_node = ip_host.find('IPAddress')
        desc_node = ip_host.find('Description')

        if name_node is not None and ip_node is not None:
            name = name_node.text.strip().replace(" ", "_") # FortiGate prefers no raw spaces in CLI without quotes
            ip = ip_node.text.strip()
            desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""

            cli_commands.append(f'    edit "{name}"')
            cli_commands.append(f'        set subnet {ip} 255.255.255.255')
            if desc:
                # Truncate comment if it exceeds FortiGate's CLI limits (typically 255 chars)
                cli_commands.append(f'        set comment "{desc[:250]}"')
            cli_commands.append('    next')
            object_count += 1

    # 2. Process Network/Subnet Blocks
    for net_host in root.findall('.//Network'):
        name_node = net_host.find('Name')
        ip_node = net_host.find('IPAddress')
        subnet_node = net_host.find('Subnet')
        desc_node = net_host.find('Description')

        if name_node is not None and ip_node is not None and subnet_node is not None:
            name = name_node.text.strip().replace(" ", "_")
            ip = ip_node.text.strip()
            subnet = subnet_node.text.strip()
            desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""

            cli_commands.append(f'    edit "{name}"')
            cli_commands.append(f'        set subnet {ip} {subnet}')
            if desc:
                cli_commands.append(f'        set comment "{desc[:250]}"')
            cli_commands.append('    next')
            object_count += 1

    cli_commands.append("end")

    # Write output to text file
    with open(output_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(cli_commands))

    print(f"Success! Processed {object_count} firewall address objects.")
    print(f"FortiGate CLI configuration script saved to: {output_txt_path}")

if __name__ == "__main__":
    # Change these paths to match your local file names
    INPUT_XML = "Entities.xml"
    OUTPUT_TXT = "fortigate_addresses.txt"

    convert_sophos_to_fortigate(INPUT_XML, OUTPUT_TXT)
