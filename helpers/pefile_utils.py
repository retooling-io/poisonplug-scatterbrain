"""PE image manipulation that aid in rebuilding the deobfuscated binary
Only known properties that need to be transformed are utilied and never
the direct protected image itself. It simplifies the logic here esp.
when all of this was being figured out on the fly.

Functions:
    build_memory_image
    build_memory_image_with_imports          (for full and selective protections)
    build_from_headerless_image_with_imports (headerless protections only)
    build_import_table

"""
import pefile
from struct import pack as PACK
from dataclasses import dataclass

# @TODO: add logging for this whole file

#-------------------------------------------------------------------------------
def build_memory_image(
    pe: pefile.PE,
    as_pefile: bool=False
) -> pefile.PE | bytearray:
    """Given a valid pefile, create a quick complete memory image of it either as
    a new pefile of the direct underlying image buffer (bytearray).

    Quick means only the no other cases are handled, which could effect
    execution in certain cases, depending on the binary rewritten. This
    is solely meant to get a static image to throw into IDA although it
    is still capable of running.
    """
    # @TODO: never use this api again, it does the base minimum and also doesn't clear header data
    mapped_img: bytearray = pe.get_memory_mapped_image()

    # force the SizeOfImage since it's guaranteed to be aligned
    mapped = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    mapped[:len(mapped_img)] = mapped_img

    # clear header data
    if pe.OPTIONAL_HEADER.SizeOfHeaders == 0x400:
        mapped[0x400:0x1000] = bytearray(0xc00)
        rva = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfHeaders")
        mapped[rva:rva+4] = PACK("<I", 0x1000)

    # adjust FileAlignment field
    rva = pe.OPTIONAL_HEADER.get_field_absolute_offset("FileAlignment")
    mapped[rva:rva+4] = PACK("<I", pe.OPTIONAL_HEADER.SectionAlignment)

    # adjust section header
    for s in pe.sections:
        prd_rva = s.get_field_absolute_offset("PointerToRawData")
        srd_rva = s.get_field_absolute_offset("SizeOfRawData")
        va = s.VirtualAddress; vs = s.Misc_VirtualSize
        mapped[prd_rva:prd_rva+4] = PACK("<I", va)
        mapped[srd_rva:srd_rva+4] = PACK("<I", vs)

    return pefile.PE(data=mapped) if as_pefile else mapped

#-------------------------------------------------------------------------------
PAGE_SIZE = 0x1000
def page_align_pad(size: int) -> int: return (PAGE_SIZE - (size % PAGE_SIZE)) % PAGE_SIZE

#-------------------------------------------------------------------------------
def build_memory_image_with_imports(
    pe: pefile.PE,
    imports_map: dict[str, set[str]],
    clear_text: bool = False,
    section_name: bytes = b".idata"
) -> tuple[pefile.PE, dict[str,int]]:
    """
    Create a new pefile from an existing one with a new import section appended at the end of it.
    The data within the existing pefile i.e, text section etc. is left intact. If you want a cleared
    text section (i.e., when rebuilding fully protected samples) set the clear_text flag.

    This was quick win code, perhaps revist at some point.

    :pe: pefile.PE         parent pefile to build off of
    :imports_map: dict[str, set[str]] dict[DllName, set[ApiName]]
    :clear_text: bool      flag that indicates whether the .text section should be null'd
    :section_name: bytes   new import section name, defaults to '.idata'

    :return: tuple[pefile.PE, dict[ApiName,RVA]]
    """
    #---------------------------------------------------------------------------
    # build the new memory image from the existing pefile representation of it
    # it will be section (page) aligned by default
    newimgbuffer: bytearray = build_memory_image(pe, as_pefile=False)
    #---------------------------------------------------------------------------
    # (1) build the serialized import descriptor table and import map
    # (2) extend the new imgbuffer to account for the added import table
    # (3) build the new import section header
    IMP_SECTION_RVA = len(newimgbuffer)
    (
        import_to_rva_map,    # dict[ApiName, RVA] 
        serialized_imp_table  # bytearray
    ) = build_import_table(imports_map, IMP_SECTION_RVA)
    #---------------------------------------------------------------------------
    newimgbuffer.extend(bytearray(serialized_imp_table))
    padding_needed = page_align_pad(len(serialized_imp_table))
    newimgbuffer.extend(bytearray(padding_needed))
    IMP_SIZE = len(serialized_imp_table) + padding_needed
    #---------------------------------------------------------------------------
    # @NOTE: all fields need to be explicit for `pack` to be happy in serializing it
    imp_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    imp_section.Name                   = section_name
    imp_section.PointerToRawData       = IMP_SECTION_RVA
    imp_section.VirtualAddress         = IMP_SECTION_RVA
    imp_section.SizeOfRawData          = IMP_SIZE
    imp_section.Misc                   = IMP_SIZE
    imp_section.Misc_VirtualSize       = IMP_SIZE
    imp_section.Characteristics        = 0xC0000000
    imp_section.PointerToRelocations   = 0
    imp_section.PointerToLinenumbers   = 0
    imp_section.NumberOfRelocations    = 0
    imp_section.NumberOfLinenumbers    = 0
    imp_sechdr_rva = (
        pe.sections[-1].get_field_absolute_offset("Name") +
        imp_section.sizeof()
    )
    imp_serialized = imp_section.__pack__()
    newimgbuffer[imp_sechdr_rva:imp_sechdr_rva+imp_section.sizeof()] = imp_serialized
    #---------------------------------------------------------------------------
    def WRITE(rva, granularity, value):
        match granularity:
            case 2: newimgbuffer[rva:rva+2] = PACK("<H", value)
            case 4: newimgbuffer[rva:rva+4] = PACK("<I", value)
            case 8: newimgbuffer[rva:rva+8] = PACK("<Q", value)

    # FILE_HEADER
    NumberOfSections = pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections")
    WRITE(NumberOfSections, 2, pe.FILE_HEADER.NumberOfSections+1)

    # OPTIONAL_HEADER
    SizeOfCode            = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfCode")
    SizeOfInitializedData = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData")
    AddressOfEntryPoint   = pe.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
    SizeOfImage           = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")

    WRITE(AddressOfEntryPoint, 4, 0x1000)                # @TODO: revisit this
    WRITE(SizeOfImage, 4, len(newimgbuffer))             # file/sec aligned already prior

    # @TODO: log
    print("Assuming the .text section is always first, always followed by the .data section")
    TEXT_SECTION_SIZE = pe.sections[0].Misc_VirtualSize
    DATA_SECTION_SIZE = pe.sections[1].Misc_VirtualSize
    WRITE(SizeOfCode, 4, TEXT_SECTION_SIZE)
    WRITE(SizeOfInitializedData, 4, DATA_SECTION_SIZE)
    #---------------------------------------------------------------------------
    # DATA_DIRECTORY (IMPORT, IAT, BASE_RELOCS)
    def _get_data_directory_info(index) -> tuple[int,int]:
        data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index] 
        return (
            data_directory.get_field_absolute_offset("VirtualAddress"),
            data_directory.get_field_absolute_offset("Size")
        )

    ImpDescRva, ImpDescSize = _get_data_directory_info(1)
    IMP_DESCS_SIZE = len(imports_map) + 1 * 0x14  # 1 for the null-descriptor
    WRITE(ImpDescRva, 4,  IMP_SECTION_RVA); WRITE(ImpDescSize, 4, IMP_DESCS_SIZE)

    IATRva, IATSize = _get_data_directory_info(12)
    WRITE(IATRva, 4, 0); WRITE(IATSize, 4, 0)

    # @NOTE: imports on the full protected binaries are handled via relocation
    BaseRelocsRva, BaseRelocsSize = _get_data_directory_info(5)
    WRITE(BaseRelocsRva, 4, 0); WRITE(BaseRelocsSize, 4, 0)
    #---------------------------------------------------------------------------
    if clear_text:
        text_size = pe.sections[0].Misc_VirtualSize;
        newimgbuffer[0x1000:0x1000+text_size] = bytearray(text_size)
    #---------------------------------------------------------------------------
    return pefile.PE(data=newimgbuffer), import_to_rva_map

#-------------------------------------------------------------------------------
x64_HEADERLESS_TEMPLATE = bytearray(
    b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
    b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xF0\x00\x00\x00"
    b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x54\x68"
    b"\x69\x73\x20\x70\x72\x6F\x67\x72\x61\x6D\x20\x63\x61\x6E\x6E\x6F"
    b"\x74\x20\x62\x65\x20\x72\x75\x6E\x20\x69\x6E\x20\x44\x4F\x53\x20"
    b"\x6D\x6F\x64\x65\x2E\x0D\x0D\x0A\x24\x00\x00\x00\x00\x00\x00\x00"
    b"\x86\x9C\x84\xF2\xC2\xFD\xEA\xA1\xC2\xFD\xEA\xA1\xC2\xFD\xEA\xA1"
    b"\xCB\x85\x79\xA1\x9C\xFD\xEA\xA1\x89\x85\xEE\xA0\xC8\xFD\xEA\xA1"
    b"\x89\x85\xE9\xA0\xC6\xFD\xEA\xA1\x89\x85\xEF\xA0\xDD\xFD\xEA\xA1"
    b"\x89\x85\xEB\xA0\xC5\xFD\xEA\xA1\xC2\xFD\xEB\xA1\xA6\xF8\xEA\xA1"
    b"\x89\x85\xE2\xA0\xDE\xFD\xEA\xA1\x89\x85\x17\xA1\xC3\xFD\xEA\xA1"
    b"\x89\x85\x15\xA1\xC3\xFD\xEA\xA1\x89\x85\xE8\xA0\xC3\xFD\xEA\xA1"
    b"\x52\x69\x63\x68\xC2\xFD\xEA\xA1\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x50\x45\x00\x00\x64\x86\x03\x00\x79\x39\xB3\x34\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\xF0\x00\x22\x00\x0B\x02\x0A\x00\xFF\xFF\xFF\xFF"
    b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00"
    b"\x00\x00\x00\x40\x01\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00"
    b"\x05\x00\x02\x00\x0A\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"
    b"\xFF\xFF\xFF\xFF\x00\x10\x00\x00\xA9\x36\x06\x00\x03\x00\x20\xC1"
    b"\x00\x00\x08\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00\x00\x00\x00"
    b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x60\x08\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x01\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\xD8\x71\x08\x00\x2F\x0F\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x2E\x74\x65\x78\x74\x00\x00\x00"
    b"\x00\x10\x06\x00\x00\x10\x00\x00\x00\x10\x06\x00\x00\x10\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60"
    b"\x2E\x64\x61\x74\x61\x00\x00\x00\x00\x40\x02\x00\x00\x20\x06\x00"
    b"\x00\x40\x02\x00\x00\x20\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x40\x00\x00\xC0\x2E\x69\x64\x61\x74\x61\x00\x00"
    b"\x00\x20\x00\x00\x00\x60\x08\x00\x00\x20\x00\x00\x00\x60\x08\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC0"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)
assert len(x64_HEADERLESS_TEMPLATE) == 0x1000

"""Mandatory Properties that need to be addressed:

DOS_HEADER: nothing
NT_HEADERS: nothing
FILE_HEADER:
    NumberOfSections := hardcoded to 3 in template (given that's consistent with all data seen)
OPTIONAL_HEADER:
    SizeOfCode              := text_section_size (or data_section_rva since it immediately follows)
    SizeOfInitializedData   := data_section_size
    SizeOfUninitializedData := hardcode to 0
    AddressOfEntryPoint     := user-specified (or hardcoded to 0x1000 since that's first rewritten function)
    BaseOfCode              := hardcoded 0x1000
    BaseOfData              := data_section_rva
    ImageBase               := same
    SectionAlignment == FileAlignment (already set)
    SizeOfImage             := len(final_aligned_imgbuffer)
    SizeOfHeades            := hardcoded 0x1000
    CheckSum                := maybe add this to be valid?
DATA_DIRECTORY[]:
    IMPORTS: 
    IAT:
"""

# ones set with 0xFFFFFFF markers in templated are expected to be updated
@dataclass
class TemplateHeaderOffsets:
    # FileHeader
    NumberOfSections:      int = 0xF6  # WORD  (3 is default)
    # OptionalHeader
    SizeOfCode:            int = 0x10C # DWORD
    SizeOfInitializedData: int = 0x110 # DWORD
    AddressOfEntryPoint:   int = 0x118 # DWORD
    SizeOfImage:           int = 0x140 # DWORD
    CheckSum:              int = 0x148 # DWORD
    # DataDirectory
    ImportsRVA:            int = 0x180 # DWORD
    ImportsSize:           int = 0x184 # DWORD
    IATRVA:                int = 0x1D8 # DWORD
    IATSize:               int = 0x1DC # DWORD
    # Sections
    CodeStart:             int = 0x1F8 # IMAGE_SECTION_HEADER
    DataStart:             int = 0x220 # IMAGE_SECTION_HEADER
    iDataStart:            int = 0x248 # IMAGE_SECTION_HEADER
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def build_from_headerless_image_with_imports(
    full_imgbuffer: bytearray,
    data_section_rva: int,
    data_section_size: int,
    imports_map: dict[str, set[str]]
) -> tuple[pefile.PE, dict[str,int]]:
    """Given a headerless protected image, rebuild its output image.

    Logic is centralized around the fact that all known headerless inputs have consisted solely of
    .text and .data section. Nothing outside of these two has been seen. The logic here goes with
    that assumption and further adds a new, recovered import directory alongside it.
    """
    # 0 -> TEXT_SECTION_SIZE (DATA_SECTION_RVA) + DATA_SECTION_SIZE
    INCOMING_LENGTH = len(full_imgbuffer)
    if INCOMING_LENGTH != data_section_rva + data_section_size:
        raise ValueError('unexpected size')

    # should already be page aligned, just adding a single page
    newimgbuffer = bytearray(len(x64_HEADERLESS_TEMPLATE) + len(full_imgbuffer))
    newimgbuffer[:0x1000] = x64_HEADERLESS_TEMPLATE[:]

    # copy over existing data section contents directly and align/pad out rest of it
    newimgbuffer[data_section_rva:] = full_imgbuffer[data_section_rva:]
    required_padding = (PAGE_SIZE - (len(newimgbuffer) % PAGE_SIZE)) % PAGE_SIZE
    required_padding = page_align_pad(len(newimgbuffer))
    newimgbuffer.extend(bytearray(required_padding))

    # --------------------------------------------------------------------------
    # @NOTE: all fields need to be explicit for `pack` to be happy in serializing it
    text_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    data_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    imp_section  = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)

    TEXT_SECTION_RVA:  int = 0x1000                # always assuming this as start
    TEXT_SECTION_SIZE: int = data_section_rva - 0x1000
    text_section.Name                   = b".text"
    text_section.PointerToRawData       = TEXT_SECTION_RVA
    text_section.VirtualAddress         = TEXT_SECTION_RVA
    text_section.SizeOfRawData          = TEXT_SECTION_SIZE 
    text_section.Misc                   = TEXT_SECTION_SIZE 
    text_section.Misc_VirtualSize       = TEXT_SECTION_SIZE 
    text_section.Characteristics        = 0x60000020
    text_section.PointerToRelocations   = 0
    text_section.PointerToLinenumbers   = 0
    text_section.NumberOfRelocations    = 0
    text_section.NumberOfLinenumbers    = 0
    text_serialized  = text_section.__pack__()

    DATA_SECTION_RVA:  int = data_section_rva
    DATA_SECTION_SIZE: int = data_section_size
    data_section.Name                   = b".data"
    data_section.PointerToRawData       = DATA_SECTION_RVA
    data_section.VirtualAddress         = DATA_SECTION_RVA
    data_section.SizeOfRawData          = DATA_SECTION_SIZE
    data_section.Misc                   = DATA_SECTION_SIZE
    data_section.Misc_VirtualSize       = DATA_SECTION_SIZE
    data_section.Characteristics        = 0xC0000040
    data_section.PointerToRelocations   = 0
    data_section.PointerToLinenumbers   = 0
    data_section.NumberOfRelocations    = 0
    data_section.NumberOfLinenumbers    = 0
    data_serialized  = data_section.__pack__()

    # (1) build the serialized import descriptor table and import map
    # (2) extend the new imgbuffer to account for the added import table
    # (3) build the new import section header
    IMP_SECTION_RVA = len(newimgbuffer)
    (
        import_to_rva_map,                               # dict[ApiName, RVA] 
        serialized_imp_table                             # bytearray
    ) = build_import_table(imports_map, IMP_SECTION_RVA)

    newimgbuffer.extend(bytearray(serialized_imp_table))
    padding_needed = page_align_pad(len(serialized_imp_table))
    newimgbuffer.extend(bytearray(padding_needed))
    IMP_SIZE = len(serialized_imp_table) + padding_needed

    imp_section.Name                   = b".idata"
    imp_section.PointerToRawData       = IMP_SECTION_RVA
    imp_section.VirtualAddress         = IMP_SECTION_RVA
    imp_section.SizeOfRawData          = IMP_SIZE
    imp_section.Misc                   = IMP_SIZE
    imp_section.Misc_VirtualSize       = IMP_SIZE
    imp_section.Characteristics        = 0xC0000000
    imp_section.PointerToRelocations   = 0
    imp_section.PointerToLinenumbers   = 0
    imp_section.NumberOfRelocations    = 0
    imp_section.NumberOfLinenumbers    = 0
    imp_serialized  = imp_section.__pack__()

    # ----------------------------------------------------------------------------------------------
    Offsets = TemplateHeaderOffsets

    def PACK_INTO_SECTION(rva, size, data): newimgbuffer[rva:rva+size] = data
    SectionSize: int = 0x28
    PACK_INTO_SECTION(Offsets.CodeStart, SectionSize, text_serialized)
    PACK_INTO_SECTION(Offsets.DataStart, SectionSize, data_serialized)
    PACK_INTO_SECTION(Offsets.iDataStart, SectionSize, imp_serialized)

    def WRITE(rva, granularity, value):
        match granularity:
            case 2: newimgbuffer[rva:rva+2] = PACK("<H", value)
            case 4: newimgbuffer[rva:rva+4] = PACK("<I", value)
            case 8: newimgbuffer[rva:rva+8] = PACK("<Q", value)

    # OPTIONAL_HEADER
    WRITE(Offsets.SizeOfCode, 4, TEXT_SECTION_SIZE)
    WRITE(Offsets.SizeOfInitializedData, 4, DATA_SECTION_SIZE)
    WRITE(Offsets.AddressOfEntryPoint, 4, 0x1000)                # @TODO: revisit this
    WRITE(Offsets.SizeOfImage, 4, len(newimgbuffer))             # file/sec aligned already prior

    # DATA_DIRECTORY
    IMP_DESCS_SIZE = len(imports_map) + 1 * 0x14                 # 1 for the null-descriptor
    WRITE(Offsets.ImportsRVA, 4, IMP_SECTION_RVA)
    WRITE(Offsets.ImportsSize, 4, IMP_DESCS_SIZE)
    WRITE(Offsets.IATRVA, 4, 0)                                  # @TODO: do I care?
    WRITE(Offsets.IATSize, 4, 0)

    return pefile.PE(data=newimgbuffer), import_to_rva_map


#-------------------------------------------------------------------------------
"""
0:000> dt combase!_IMAGE_IMPORT_DESCRIPTOR
   +0x000 OriginalFirstThunk : Uint4B
   +0x004 TimeDateStamp    : Uint4B
   +0x008 ForwarderChain   : Uint4B
   +0x00c Name             : Uint4B
   +0x010 FirstThunk       : Uint4B

0:000> dt combase!IMAGE_THUNK_DATA .
   +0x000 u1               :
      +0x000 ForwarderString  : Uint8B
      +0x000 Function         : Uint8B
      +0x000 Ordinal          : Uint8B
      +0x000 AddressOfData    : Uint8B

0:000> dt combase!_IMAGE_IMPORT_BY_NAME
   +0x000 Hint             : Uint2B
   +0x002 Name             : [1] Char
"""
# return the ImportToRVA && SerializedImportTable

def build_import_table(
    imports: dict[str,
    set[str]],
    base_rva=0
) -> tuple[dict[str,int], bytearray]:
    """

    :imports: dict[DllName, set[ApiName]]
    :base_rva: int  RVA of where the import table is expected to be at
                    in the image

    Example input:
    'ADVAPI32.dll': {'CryptAcquireContextW',
                     'CryptCreateHash',
                     'CryptDecrypt',
                     'CryptDeriveKey',
                     'CryptDestroyHash',
                     'CryptDestroyKey',
                     'CryptEncrypt', ...}

    :return: tuple[dict[ApiName,RVA], bytearray]
        - import_rva_map: dict[ApiName, RVA]
        - serialized_table

         IMAGE_IMPORT_DESCRIPTOR []
        +--------------------------+
        | OriginalFirstThunk (RVA) |
        | Time Data Stamp          |
        | ForwarderChain           |
        | Name               (RVA) |
        | FirstThunk         (RVA) |
        +------------+-------------+
        |            0             |
        +------------+-------------+
                     |
                DLL_NAMES []
        +--------------------------+
        | KERNEL32.DLL\0           |
        | ADVAPI32.DLL\0           |
        | \0                       |
        +------------+-------------+
                     |
           API_NAMES [] (hint,api)
        +--------------------------+
        | 00 00 | GetProcAddress\0 |
        | 00 00 | LoadLibraryW\0   |
        | 00 00 | \0               |
        +------------+-------------+
                     |
                  INT []
        +--------------------------+
        | AddressOfData      (RVA) |
        | AddressOfData      (RVA) |
        | 0                        |
        +------------+-------------+
                     |
                  IAT []
        +------------+-------------+
        | Function (RVA)           |
        | Function (RVA)           |
        | 0                        |
        +--------------------------+
    """
    #---------------------------------------------------------------------------
    # pre-calculate the sizes
    #   - `20` == sizeof(IMAGE_IMPORT_DESCRIPTOR)
    #   - +1 for the null descriptor
    #   - +1 for null terminator
    #   - +3 hint and null terminator
    dll_count      = len(imports)
    desc_size      = (dll_count + 1) * 20
    dll_names_size = sum(len(dll) + 1 for dll in imports.keys())
    api_names_size = sum(len(api) + 3
                          for apis in imports.values()
                          for api in apis)
    num_apis     = sum(len(fn) for fn in imports.values())
    int_iat_size = (num_apis + dll_count) * 8
    #---------------------------------------------------------------------------
    total_size = (desc_size      +
                  dll_names_size +
                  api_names_size +
                  int_iat_size)
    #---------------------------------------------------------------------------
    # allocate space for each component
    descs      = bytearray(desc_size)
    dll_names  = bytearray(dll_names_size)
    api_names  = bytearray(api_names_size)
    INT        = bytearray(int_iat_size)
    IAT        = bytearray(int_iat_size)

    #---------------------------------------------------------------------------
    # mapping of import names to their new int_rva, for post-process patching
    import_rva_mapping: dict[str,int] = {}

    #---------------------------------------------------------------------------
    # offsets/indexes for each relevant component
    (
        dll_offset, # current index into the dll_names storage
        api_offset, # current index into the api_names storage
        int_offset, # current index into the INT storage
        iat_offset  # current index into the IAT storage
    ) = 0,0,0,0

    #---------------------------------------------------------------------------
    # build the table contents
    for i, (dll, apis) in enumerate(imports.items()):
        # descriptor: OFT, Name, FT
        desc_offset = i * 20
        descs[desc_offset:desc_offset+4] = PACK('<I',
                                                (base_rva +
                                                 desc_size +
                                                 dll_names_size +
                                                 api_names_size +
                                                 int_offset))

        descs[desc_offset+12:desc_offset+16] = PACK('<I',
                                                    (base_rva +
                                                     desc_size +
                                                     dll_offset))

        descs[desc_offset+16:desc_offset+20] = PACK('<I',
                                                    (base_rva +
                                                     desc_size +
                                                     dll_names_size +
                                                     api_names_size +
                                                     iat_offset))
        
        # dll names storage
        dll_names[dll_offset:dll_offset+len(dll)+1] = (dll.encode('ascii') +
                                                       b'\x00')
        dll_offset += len(dll) + 1

        # function names  INT/IAT
        for api in apis:
            # hint + name (+3 hint/name/null-terminator)
            api_names[api_offset:api_offset+2] = PACK('<H', 0)
            api_names[api_offset+2:
                      api_offset+2+len(api)+1] = (api.encode('ascii') +
                                                   b'\x00')

            # curr int/iat_rva
            int_rva = (base_rva +
                       desc_size +
                       dll_names_size +
                       api_offset)

            # udpate api index
            api_offset += len(api) + 3

            # update the thunk entries
            INT[int_offset:int_offset+8] = PACK('<Q', int_rva)
            IAT[iat_offset:iat_offset+8] = PACK('<Q', int_rva)

            # update the impname-rva mapping
            iat_entry_rva = (base_rva +
                             desc_size +
                             dll_names_size +
                             api_names_size +
                             iat_offset)
            import_rva_mapping[api] = iat_entry_rva

            # update thunk indexes
            int_offset += 8
            iat_offset += 8
        #----------------------------------------------------------------------
        # null terminate INT and IAT for this descriptor
        int_offset += 8; iat_offset += 8
    #--------------------------------------------------------------------------
    # ensure the final descriptor itself is null-terminated
    descs[-20:] = b'\x00' * 20

    # return the ImportToRVA && SerializedImportTable
    return (
        import_rva_mapping,                        # dict[ApiName, RVA]
        descs + dll_names + api_names + INT + IAT  # serialized table
    )