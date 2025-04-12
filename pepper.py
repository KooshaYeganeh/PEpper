from modules import banner
from modules import argv
from modules import run
from modules import output
import sys
import os

# Define the directory path for Pepper
Pepperdir = "/tmp/Pepper"
# Create the directory if it doesn't exist
os.makedirs(Pepperdir, exist_ok=True)


def main():
    argv.get()  # Assuming this does something with arguments
    banner.get()  # Assuming this shows some banner or info
    filename = sys.argv[1]  # Get the filename passed as argument

    # Open the CSV file in write mode inside a context manager
    with open(f"{Pepperdir}/Pepper.csv", 'w') as csv:
        # Write headers to CSV file
        csv.write("id,susp_entrop_ratio,susp_name_ratio,susp_code_size,imphash,n_exports,n_antidbg,n_antivm,n_susp_api,"
                  "has_gs, "
                  "has_cfg,has_dep,has_aslr,has_seh,has_tls,susp_dbg_ts,n_url,n_ip,has_manifest,has_version,"
                  "n_susp_strings,is_packed,"
                  "has_certificate,"
                  "susp_virustotal_ratio,n_yara_rules")
        
        # Run some process with the file
        run.get(filename, csv)
    
    # Output result
    output.get(filename)


if __name__ == "__main__":
    main()

