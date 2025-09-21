import lief
from . import colors

# Set logging level
if hasattr(lief.logging, "LEVEL"):
    lief.logging.set_level(lief.logging.LEVEL.ERROR)
elif hasattr(lief.logging, "Level"):
    lief.logging.set_level(lief.logging.Level.ERROR)
else:
    lief.logging.disable()


# check if PE has a version
def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "VERSION", " -------------------------------") + colors.DEFAULT))

    binary = lief.parse(malware)

    if not binary.has_resources or not binary.resources_manager.has_version:
        print((colors.RED + "[X]" + colors.DEFAULT + " PE has no version"))
        csv.write("0,")
        return

    print((colors.GREEN + "[✓]" + colors.DEFAULT + " PE has a version"))
    csv.write("1,")

    # Iterate over version resources
    for ver in binary.resources_manager.version:
        sfi = ver.string_file_info
        if sfi is not None:
            for table in sfi.children:  # ResourceStringTable objects
                for entry in table.entries:  # entry is an entry_t object
                    key = entry.key
                    value = entry.value
                    print(f"{key}: {value}")
