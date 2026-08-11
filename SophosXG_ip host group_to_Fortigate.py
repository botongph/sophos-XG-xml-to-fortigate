import xml.etree.ElementTree as ET
import sys
import os

def convert_sophos_groups_to_fortigate(xml_file_path, output_txt_path):
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

    cli_commands = ["config firewall addrgrp"]
    group_count = 0

    # Sophos stores IP Groups under <IPHostGroup> or <IPGroup> tags
    groups = root.findall('.//IPHostGroup') + root.findall('.//IPGroup')

    for group in groups:
        name_node = group.find('Name')
        desc_node = group.find('Description')
        host_list_node = group.find('HostList')

        if name_node is not None and host_list_node is not None:
            # Format group name for FortiGate CLI (spaces replaced with underscores)
            group_name = name_node.text.strip().replace(" ", "_")
            desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""

            # Extract all member hosts assigned to this group
            members = []
            for host in host_list_node.findall('Host'):
                if host.text:
                    # Sanitize member names to match the names created by the first script
                    member_name = host.text.strip().replace(" ", "_")
                    members.append(f'"{member_name}"')

            # Only create the group in FortiGate if it contains members
            if members:
                cli_commands.append(f'    edit "{group_name}"')
                # FortiGate handles members as a space-separated list inside quotes or separated by spaces
                cli_commands.append(f'        set member {" ".join(members)}')
                if desc:
                    cli_commands.append(f'        set comment "{desc[:250]}"')
                cli_commands.append('    next')
                group_count += 1

    cli_commands.append("end")

    # Write the output to a text file
    with open(output_txt_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(cli_commands))

    print(f"Success! Processed {group_count} firewall address groups.")
    print(f"FortiGate CLI configuration script saved to: {output_txt_path}")

if __name__ == "__main__":
    INPUT_XML = "Entities.xml"
    OUTPUT_TXT = "fortigate_groups.txt"

    convert_sophos_groups_to_fortigate(INPUT_XML, OUTPUT_TXT)

