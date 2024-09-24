import lief
from . import colors

# Check if PE file uses Structured Exception Handling (SEH)
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "SEH", " -------------------------------") + colors.DEFAULT))

    binary = lief.parse(malware)

    # Define the NO_SEH flag
    NO_SEH_FLAG = 0x0400

    # Check if the NO_SEH flag is set
    if binary.optional_header.dll_characteristics & NO_SEH_FLAG:
        print((colors.RED + "[X]" + colors.DEFAULT + " The file doesn't support Structured Exception Handling (SEH)"))
        csv.write("0,")
    else:
        print((colors.GREEN + "[" + '\u2713' +
               "]" + colors.DEFAULT + " The file supports Structured Exception Handling (SEH)"))
        csv.write("1,")
