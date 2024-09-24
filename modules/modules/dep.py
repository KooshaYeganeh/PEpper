import lief
from . import colors

# Check if PE supports Data Execution Prevention (DEP)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "DEP", " -------------------------------") + colors.DEFAULT))

    binary = lief.parse(malware)

    # Define NX_COMPAT flag
    NX_COMPAT_FLAG = 0x0100

    # Check if DEP (NX_COMPAT) is enabled
    if binary.optional_header.dll_characteristics & NX_COMPAT_FLAG:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Data Execution Prevention (DEP)"))
        csv.write("1,")
    else:
        print((
            colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Data Execution Prevention (DEP)"))
        csv.write("0,")
