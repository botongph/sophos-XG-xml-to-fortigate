import xml.etree.ElementTree as ET
import os
import sys

def extract_fqdn_to_fortigate(xml_path, output_path):
    if not os.path.exists(xml_path):
        print(f"Error: Missing file '{xml_path}' in this folder.")
        sys.exit(1)

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as err:
        print(f"XML Parsing Exception: {err}")
        sys.exit(1)

    address_cli = ["config firewall address"]
    group_cli = ["config firewall addrgrp"]

    fqdn_count = 0
    group_count = 0

    # Process all XML elements recursively
    all_elements = root.findall('.//*')

    for elem in all_elements:
        tag_lower = elem.tag.lower()

        # --- 1. PARSE FQDN HOSTS ---
        # Matches <FQDNHost>, or standard <IPHost> elements configured as FQDNs
        is_fqdn_host = (tag_lower == 'fqdnhost')

        # Check for Sophos combined schemas (<IPHost> where <HostType> is FQDN)
        host_type_node = elem.find('HostType') or elem.find('hosttype')
        if host_type_node is not None and host_type_node.text:
            if host_type_node.text.strip().upper() == 'FQDN':
                is_fqdn_host = True

        if is_fqdn_host:
            # Resolve nodes cleanly using explicit 'is not None' checks for Python 3.13+
            name_node = elem.find('Name') if elem.find('Name') is not None else elem.find('name')
            fqdn_node = elem.find('FQDN') if elem.find('FQDN') is not None else (
                        elem.find('fqdn') if elem.find('fqdn') is not None else elem.find('FQDNUrl'))
            desc_node = elem.find('Description') if elem.find('Description') is not None else elem.find('description')

            if name_node is not None and fqdn_node is not None:
                if name_node.text and fqdn_node.text:
                    clean_name = name_node.text.strip().replace(" ", "_").replace('"', "")
                    domain_val = fqdn_node.text.strip().lower().replace('"', "")

                    # Strip any accidental wildcards that break standard FQDN objects
                    if domain_val.startswith("*."):
                        domain_val = domain_val.replace("*.", "")

                    comment = desc_node.text.strip() if (desc_node is not None and desc_node.text) else ""

                    address_cli.append(f'    edit "{clean_name}"')
                    address_cli.append(f'        set type fqdn')
                    address_cli.append(f'        set fqdn "{domain_val}"')
                    if comment:
                        address_cli.append(f'        set comment "{comment[:250]}"')
                    address_cli.append('    next')
                    fqdn_count += 1

        # --- 2. PARSE FQDN GROUPS ---
        is_fqdn_group = (tag_lower == 'fqdnhostgroup' or tag_lower == 'fqdngroup')
        if is_fqdn_group:
            name_node = elem.find('Name') if elem.find('Name') is not None else elem.find('name')
            desc_node = elem.find('Description') if elem.find('Description') is not None else elem.find('description')
            fqdn_list = elem.find('FQDNList') if elem.find('FQDNList') is not None else (
                        elem.find('fqdnlist') if elem.find('fqdnlist') is not None else elem.find('HostList'))

            if name_node is not None and name_node.text and fqdn_list is not None:
                grp_name = name_node.text.strip().replace(" ", "_").replace('"', "")
                comment = desc_node.text.strip() if (desc_node is not None and desc_node.text) else ""

                members = []
                for sub_node in fqdn_list.findall('.//*'):
                    if sub_node.text and sub_node.tag.lower() in ['fqdn', 'host', 'name']:
                        m_name = sub_node.text.strip().replace(" ", "_").replace('"', "")
                        members.append(f'"{m_name}"')

                if members:
                    group_cli.append(f'    edit "{grp_name}"')
                    group_cli.append(f'        set member {" ".join(members)}')
                    if comment:
                        group_cli.append(f'        set comment "{comment[:250]}"')
                    group_cli.append('    next')
                    group_count += 1

    address_cli.append("end\n")
    group_cli.append("end")

    final_output = []
    if fqdn_count > 0:
        final_output.extend(address_cli)
    if group_count > 0:
        final_output.extend(group_cli)

    if fqdn_count == 0 and group_count == 0:
        print("⚠️ Warning: No explicit FQDN elements detected. The XML schema might match a different layout version.")
        return

    with open(output_path, 'w', encoding='utf-8') as outfile:
        outfile.write("\n".join(final_output))

    print(f"🎉 Success!")
    print(f"Parsed FQDN Hosts: {fqdn_count}")
    print(f"Parsed FQDN Groups: {group_count}")
    print(f"File committed successfully to: {output_path}")

if __name__ == "__main__":
    extract_fqdn_to_fortigate("Entities.xml", "fortigate_fqdn_output.txt")




