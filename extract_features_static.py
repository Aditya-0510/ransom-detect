# extract_features_static.py
import pefile

# Mapping dictionaries
MACHINE_NAMES = {
    0x014c: "Intel 386 or later, and compatibles",
    0x8664: "AMD AMD64",
    0x01c0: "ARM",
    0xAA64: "ARM64",
}

MAGIC_MAP = {
    0x10B: "PE32",
    0x20B: "PE32+"
}

SUBSYSTEM_NAMES = {
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"
}

def characteristics_list(flag):
    names = []
    if flag & 0x00000020: names.append("IMAGE_SCN_CNT_CODE")
    if flag & 0x00000040: names.append("IMAGE_SCN_CNT_INITIALIZED_DATA")
    if flag & 0x20000000: names.append("IMAGE_SCN_MEM_EXECUTE")
    if flag & 0x40000000: names.append("IMAGE_SCN_MEM_READ")
    return "['" + "', '".join(names) + "']" if names else "[]"

def dllchar_list(flag):
    names = []
    if flag & 0x0040: names.append("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE")
    if flag & 0x0020: names.append("IMAGE_DLLCHARACTERISTICS_NX_COMPAT")
    if flag & 0x0200: names.append("IMAGE_DLLCHARACTERISTICS_NO_SEH")
    if flag & 0x8000: names.append("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE")
    return "['" + "', '".join(names) + "']" if names else "[]"

def section_by_name(pe, name):
    for s in pe.sections:
        nm = s.Name.decode(errors="ignore").replace("\x00", "").lower()
        if nm == name.strip(".").lower():
            return s
    return None

def extract_features(path: str):
    try:
        pe = pefile.PE(path, fast_load=False)
    except:
        return None

    dos = pe.DOS_HEADER
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    machine_name = MACHINE_NAMES.get(fh.Machine, str(fh.Machine))
    magic_name = MAGIC_MAP.get(oh.Magic, "PE32")

    # Sections
    s_text = section_by_name(pe, ".text")
    s_rdata = section_by_name(pe, ".rdata")

    def safe_hex(v):
        try:
            return hex(int(v))
        except:
            return "0x0"

    def sec_attr(section, attr):
        try:
            return getattr(section, attr)
        except:
            return 0

    feats = {
        "file_extension": "exe",
        "EntryPoint": safe_hex(oh.AddressOfEntryPoint),
        "PEType": magic_name,
        "MachineType": machine_name,
        "magic_number": "MZ",

        "bytes_on_last_page": safe_hex(dos.e_cblp),
        "pages_in_file": safe_hex(dos.e_cp),
        "relocations": safe_hex(dos.e_crlc),
        "size_of_header": safe_hex(dos.e_cparhdr),
        "min_extra_paragraphs": safe_hex(dos.e_minalloc),
        "max_extra_paragraphs": safe_hex(dos.e_maxalloc),
        "init_ss_value": safe_hex(dos.e_ss),
        "init_sp_value": safe_hex(dos.e_sp),
        "init_ip_value": safe_hex(dos.e_ip),
        "init_cs_value": safe_hex(dos.e_cs),
        "over_lay_number": safe_hex(dos.e_ovno),
        "oem_identifier": safe_hex(dos.e_oemid),
        "address_of_ne_header": safe_hex(dos.e_lfanew),

        "Magic": magic_name,
        "SizeOfCode": safe_hex(oh.SizeOfCode),
        "SizeOfInitializedData": safe_hex(oh.SizeOfInitializedData),
        "SizeOfUninitializedData": safe_hex(oh.SizeOfUninitializedData),
        "AddressOfEntryPoint": safe_hex(oh.AddressOfEntryPoint),
        "BaseOfCode": safe_hex(oh.BaseOfCode),
        "BaseOfData": safe_hex(getattr(oh, "BaseOfData", 0)),
        "ImageBase": safe_hex(oh.ImageBase),
        "SectionAlignment": safe_hex(oh.SectionAlignment),
        "FileAlignment": safe_hex(oh.FileAlignment),

        "OperatingSystemVersion": float(f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}"),
        "ImageVersion": float(f"{oh.MajorImageVersion}.{oh.MinorImageVersion}"),

        "SizeOfImage": safe_hex(oh.SizeOfImage),
        "SizeOfHeaders": safe_hex(oh.SizeOfHeaders),
        "Checksum": safe_hex(oh.CheckSum),
        "Subsystem": SUBSYSTEM_NAMES.get(oh.Subsystem, "IMAGE_SUBSYSTEM_WINDOWS_GUI"),
        "DllCharacteristics": dllchar_list(oh.DllCharacteristics),

        "SizeofStackReserve": safe_hex(oh.SizeOfStackReserve),
        "SizeofStackCommit": safe_hex(oh.SizeOfStackCommit),
        "SizeofHeapCommit": safe_hex(oh.SizeOfHeapCommit),
        "SizeofHeapReserve": safe_hex(oh.SizeOfHeapReserve),
        "LoaderFlags": safe_hex(oh.LoaderFlags),

        "text_VirtualSize": safe_hex(sec_attr(s_text, "Misc_VirtualSize")),
        "text_VirtualAddress": safe_hex(sec_attr(s_text, "VirtualAddress")),
        "text_SizeOfRawData": safe_hex(sec_attr(s_text, "SizeOfRawData")),
        "text_PointerToRawData": safe_hex(sec_attr(s_text, "PointerToRawData")),
        "text_PointerToRelocations": safe_hex(sec_attr(s_text, "PointerToRelocations")),
        "text_PointerToLineNumbers": safe_hex(sec_attr(s_text, "PointerToLinenumbers")),
        "text_Characteristics": characteristics_list(sec_attr(s_text, "Characteristics")),

        "rdata_VirtualSize": safe_hex(sec_attr(s_rdata, "Misc_VirtualSize")),
        "rdata_VirtualAddress": safe_hex(sec_attr(s_rdata, "VirtualAddress")),
        "rdata_SizeOfRawData": safe_hex(sec_attr(s_rdata, "SizeOfRawData")),
        "rdata_PointerToRawData": safe_hex(sec_attr(s_rdata, "PointerToRawData")),
        "rdata_PointerToRelocations": safe_hex(sec_attr(s_rdata, "PointerToRelocations")),
        "rdata_PointerToLineNumbers": safe_hex(sec_attr(s_rdata, "PointerToLinenumbers")),
        "rdata_Characteristics": characteristics_list(sec_attr(s_rdata, "Characteristics")),
    }

    return feats
