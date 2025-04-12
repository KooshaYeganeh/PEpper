import yara
import os
import sys
import string
import csv
from . import colors

def get_yara_path(rule_file):
    """Construct the full path to the specified YARA rule file."""
    root_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(root_dir, 'rules', rule_file)

def compile_yara_rules():
    """Compile YARA rules from predefined rule files."""
    rule_files = {
        'AntiVM/DB': 'Antidebug_AntiVM_index.yar',
        'Crypto': 'Crypto_index.yar',
        'CVE': 'CVE_Rules_index.yar',
        'Exploit': 'Exploit-Kits_index.yar',
        'Document': 'Malicious_Documents_index.yar',
        'Malware': 'malware_index.yar',
        'Packers': 'Packers_index.yar',
        'Webshell': 'Webshells_index.yar'
    }
    return yara.compile(filepaths={name: get_yara_path(file) for name, file in rule_files.items()})

def print_match_info(match):
    """Print details of a matched YARA rule."""
    print(f"{colors.YELLOW}{match.rule}{colors.DEFAULT}")
    print(f"{colors.WHITE}\tType: {colors.RED}{match.namespace}{colors.DEFAULT}")
    tags = ", ".join(match.tags) if match.tags else "None"
    print(f"{colors.WHITE}\tTags: {colors.DEFAULT}{tags}")
    print(f"{colors.WHITE}\tMeta:{colors.DEFAULT}")
    
    for key, value in match.meta.items():
        print(f"{colors.WHITE}\t\t{key.capitalize()}: {colors.DEFAULT}{value}")

def process_matched_strings(strings):
    """Process and print matched strings from YARA rule matches."""
    try:
        format_str = "{:<35} {:<1} {:<1}"
        non_printable_count = 0

        for string_match in strings:
            # Access the string name (identifier) and matched string value (data)
            string_name = string_match.identifier  # Name of the string
            matched_string_value = string_match.data  # Matched string data (as bytes)

            # Decode the bytes and check if it's printable
            try:
                decoded_value = matched_string_value.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                decoded_value = matched_string_value.decode('utf-8', errors='ignore')  # Skip invalid characters

            # Check if all characters in the string are printable
            if all(c in string.printable for c in decoded_value):
                print(f"\t\t{format_str.format(decoded_value, '| Occurrences:', 1)}")
            else:
                non_printable_count += 1

        if non_printable_count > 0:
            print(f"\t\t[X] {non_printable_count} string(s) not printable")
    except Exception as e:
        print(f"ERROR on String Matches: {e}")

def get(malware, csv_file):
    """Main function to get YARA matches for the given malware file."""
    print(f"{colors.WHITE}\n------------------------------- {colors.DEFAULT} YARA RULES {colors.DEFAULT} -------------------------------{colors.DEFAULT}")

    rules = compile_yara_rules()

    with open(malware, 'rb') as f:
        matches = rules.match(data=f.read())

    with open(csv_file, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        if matches:
            for match in matches:
                print_match_info(match)
                if not match.strings:
                    print(f"{colors.WHITE}\tStrings: None")
                else:
                    print(f"{colors.WHITE}\tStrings: {colors.DEFAULT}")
                    # Process matched strings directly from match.strings
                    process_matched_strings(match.strings)
                print("\n")
            csv_writer.writerow([malware, len(matches), "Matches found"])
        else:
            print(f"{colors.RED}[X] No matches found{colors.DEFAULT}")
            csv_writer.writerow([malware, 0, "No matches"])

