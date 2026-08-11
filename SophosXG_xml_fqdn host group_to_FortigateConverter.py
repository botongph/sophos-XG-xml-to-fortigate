import xml.etree.ElementTree as ET
import os
import sys

def extract_pure_fqdn_groups(xml_path, output_path):
    if not os.path.exists(xml_path):
        print(f"Error: Missing target file '{xml_path}' in this path.")
        sys.exit(1)

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as err:
        print(f"XML Parsing Exception: {err}")
        sys.exit(1)

    group_cli = ["config firewall addrgrp"]
    group_count = 0

    # Process all XML elements recursively
    all_elements = root.findall('.//*')

    for elem in all_elements:
        tag_lower = elem.tag.lower()

        # Target FQDN Host Group tags explicitly
        if tag_lower in ['fqdnhostgroup', 'fqdngroup']:
            name_node = elem.find('Name') if elem.find('Name') is not None else elem.find('name')
            desc_node = elem.find('Description') if elem.find('Description') is not None else elem.find('description')

            # Target any child container keeping names or lists
            member_container = None
            for child in elem:
                if 'list' in child.tag.lower() or 'host' in child.tag.lower():
                    member_container = child
                    break

            # If no container tag found, default to scanning the whole FQDN group block
            if member_container is None:
                member_container = elem

            if name_node is not None and name_node.text:
                grp_name = name_node.text.strip().replace(" ", "_").replace('"', "")
                comment = desc_node.text.strip() if (desc_node is not None and desc_node.text) else ""

                # Gather every piece of text element inside this block except the group's own Name/Description
                members = []
                for sub_node in member_container.findall('.//*'):
                    if sub_node.text and sub_node.tag.lower() not in ['name', 'description', 'fqdnhostgroup', 'fqdngroup', 'fqdnlist', 'hostlist']:
                        member_name = sub_node.text.strip().replace(" ", "_").replace('"', "")
                        members.append(f'"{member_name}"')

                # Fallback: if sub_node loops missed it, look directly for specific string items
                if not members:
                    for sub_node in member_container.findall('.//*'):
                        if sub_node.text:
                            m_name = sub_node.text.strip().replace(" ", "_").replace('"', "")
                            if m_name != grp_name and m_name != comment:
                                members.append(f'"{m_name}"')

                if members:
                    group_cli.append(f'    edit "{grp_name}"')
                    group_cli.append(f'        set member {" ".join(members)}')
                    if comment:
                        group_cli.append(f'        set comment "{comment[:250]}"')
                    group_cli.append('    next')
                    group_count += 1

    group_cli.append("end")

    if group_count == 0:
        print("⚠️ Warning: No explicit FQDN groups parsed. Let's output a template instead.")
        return

    with open(output_path, 'w', encoding='utf-8') as outfile:
        outfile.write("\n".join(group_cli))

    print(f"🎉 Success!")
    print(f"Converted FQDN Groups: {group_count}")
    print(f"File committed successfully to: {output_path}")

if __name__ == "__main__":
    extract_pure_fqdn_groups("Entities.xml", "fortigate_fqdn_groups_output.txt")



