import lief
from . import colors


# check if PE file supports control flow guard


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "CFG", " -------------------------------") + colors.DEFAULT))

    binary = lief.parse(malware)

    # Control Flow Guard (CFG) is represented by the 0x4000 flag in DLLCharacteristics
    GUARD_CF_FLAG = 0x4000

    if binary.optional_header.dll_characteristics & GUARD_CF_FLAG:
        print((colors.GREEN + "[" + '\u2713' + "]" + colors.DEFAULT + " Control Flow Guard (CFG) is enabled."))
        csv.write("CFG Enabled,")
    else:
        print((colors.RED + "[X]" + colors.DEFAULT + " Control Flow Guard (CFG) is not enabled."))
        csv.write("CFG Not Enabled,")

