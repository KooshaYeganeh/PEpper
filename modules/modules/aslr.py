import lief
from . import colors

# Check if PE supports Address Space Layout Randomization (ASLR)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "ASLR", " -------------------------------") + colors.DEFAULT))

    binary = lief.parse(malware)

    # Define the DYNAMIC_BASE flag
    DYNAMIC_BASE_FLAG = 0x0040

    # Check if ASLR (DYNAMIC_BASE) is enabled
    if binary.optional_header.dll_characteristics & DYNAMIC_BASE_FLAG:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Address Space Layout Randomization (ASLR)"))
        csv.write("1,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Address Space Layout Randomization (ASLR)"))
        csv.write("0,")
