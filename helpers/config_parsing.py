__author__ = "inino@google.com"
#------------------------------------------------------------------------------
#

BlobConfigId = 0xA0000000 
BlobPluginId = 0x20000000 

# Particular sample only has 4 blobs:
# ----------------------------------
#  > 0000675E8 7B 08 00 A0  dd A000087Bh  : config, id's via `A0` marker
#  > 000067E67 24 16 00 20  dd 20001624h  : 3 modules ... ...??
#  > 00006948F 24 CC 00 20  dd 2000CC24h
#  > 0000760B7 24 FE 00 20  dd 2000FE24h

# ```
# __int64 __fastcall shadow::ConfigDecryptDeserialize(list_head_t *a1)
# {
#   // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
#   utility::BufferEmptyInit(&ft);
#   blob = shadow::ConfigScanFindBasePtr();
#   if ( blob ) {
#     // seg000:00000000000675E8 7B 08              dw 87Bh
#     // seg000:00000000000675EA 00 A0              dw 0A000h
#     // seg000:00000000000675EC 45 3C B8 99        dd 99B83C45h
#     // seg000:00000000000675F0 F8 43 7D DC        dd 0DC7D43F8h
#     // seg000:00000000000675F4 AE CE 78 7B        dd 7B78CEAEh
#     // seg000:00000000000675F8 65 4A 79 14        dd 14794A65h
#     // seg000:00000000000675FC 1B E0 55 B4        dd 0B455E01Bh
#     // seg000:0000000000067600 D0 71 56 F4        dd 0F45671D0h
#     // seg000:0000000000067604 36 6E 6A 81        dd 816A6E36h
#     // seg000:0000000000067608 80 AB E2 6B        dd 6BE2AB80h
#     // seg000:000000000006760C 32 DB A9 42        dd 42A9DB32h
# 
#     // @NOTE: `A0` identifes it's config blob
#     found = shadow::ScanDecryptLastBlobMatchingId(0xA0, &ft, blob);
#     if ( !found ) // 0 == success     
#       success = shadow::DeserializeConfigToList(a1, &ft);
# ```
#
#------------------------------------------------------------------------------
from typing import Optional, List, Any
from dataclasses import dataclass, field
import struct

#------------------------------------------------------------------------------
NodeTypeU8     = 0x1000000
NodeTypeU16    = 0x2000000
NodeTypeU32    = 0x3000000
NodeTypeU64    = 0x4000000
NodeTypeArray  = 0x5000000
NodeTypeString = 0x6000000

ConfigNodeTypes = [
    NodeTypeU8,
    NodeTypeU16,
    NodeTypeU32,
    NodeTypeU64,
    NodeTypeArray,
    NodeTypeString
]

# Comes from:
#  shadow::CryptBufferWith4ByteNonce(&v8, 0xAF7A6CAD);
# shadow::CryptBufferWith4ByteNonce(OutDecryptedBuffer, 0xEF512CF5);
#NodeStringNonce = [ 0xAD, 0x6C, 0x7A, 0xAF ]
#NodeArrayNonce  = [ 0xF5, 0x2C, 0x51, 0xEF ]
#ConfigMagicMarker = 0xD9C58B07 # @NOTE: applies to decrypted config only

NodeArrayNonce  = [ 0x3F, 0xAE, 0x16, 0xFC ]
NodeStringNonce = [ 0x67, 0xC4, 0x3E, 0x9A]
ConfigMagicMarker = 0x8e718e75

class ConfigNode:
    def __init__(self,
                 offset: int,
                 identifier: int,
                 node_type: int,
                 data: Any):
        if node_type not in ConfigNodeTypes:
            raise ValueError(f'Unknown node_type: {node_type}')

        self.offset     = offset     # in config
        self.identifier = identifier
        self.node_type  = node_type
        self._data      = data

    def __str__(self):
        if (
            self.node_type == NodeTypeString or
            self.node_type == NodeTypeArray
        ):
            data = (self._data.decode('ascii')
                    if self.node_type == NodeTypeString
                    else self._data)
            return (
                f'(+{self.offset:#08x}) <Node::{self.identifier:08x}> '
                f'{self.node_type:08x}: `'
                f'{data}`'
            )
        else:
            return (
                f'(+{self.offset:#08x}) <Node::{self.identifier:08x}> '
                f'{self.node_type:08x}: `'
                f'{self._data:x}`'
            )

    def __repr__(self):
        return self.__str__()

@dataclass
class Config:
    blob: bytearray = field(default_factory=bytearray)
    nodes: List[ConfigNode] = field(default_factory=list)

# ShadowConfig

#------------------------------------------------------------------------------
# The config is decrypted via the following utility wrapper (no symbols, all
# of my own naming). Nonce is pulled out from the last 4-bytes. This also
# decrypts any of the embedded modules.
#
# DWORD __fastcall utility::FileBufferCryptStorage(file_buffer_t *a1) {
#   // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
# 
#   size = a1->size;
#   if ( size < 4 )
#     return 13;
# 
#   Buffer = a1->Buffer;
#   // last dword w/in the blob is the nonce
#   Nonce = *&Buffer[size - 4];
#   result = shadow::CryptTransform_6301744A(
#              Buffer,
#              size - 4,
#              size - 4,
#              &outDecryptedSize,
#              &Nonce,
#              4u);
#   if ( !result )
#   {
#     a1->Offset = 0;
#     a1->size = outDecryptedSize;
#     return 0;
#   }
#   return result;
# }
#------------------------------------------------------------------------------

def deserialize_decrypted_config(config_blob, decryptor) -> Config:
    cfg = Config()

    offset = 0
    magic = struct.unpack_from('<I', config_blob, offset)[0]
    offset += 4
    if magic != ConfigMagicMarker:
        raise ValueError("Invalid magic number in config blob")

    while offset < len(config_blob):
        last_offset = offset
        node_id = struct.unpack_from('<I', config_blob, offset)[0]
        offset += 4
        node_type = node_id & 0xFF000000
        if node_type == NodeTypeArray or node_type == NodeTypeString:
            size = struct.unpack_from('<I', config_blob, offset)[0]
            offset += 4
            enc_data = config_blob[offset:offset+size]
            offset += size
            nonce = (NodeStringNonce if node_type == NodeTypeString
                     else NodeArrayNonce)
            node_data = decryptor(enc_data, len(enc_data), nonce)[1]
        else:
            if node_type == NodeTypeU8:    data_format = 'B'
            elif node_type == NodeTypeU16: data_format = 'H'
            elif node_type == NodeTypeU32: data_format = 'I'
            elif node_type == NodeTypeU64: data_format = 'Q'
            else:
                print(f"Invalid node type `{node_type:08x}` at "
                      f"offset {offset:08x}")
                break
                ##raise ValueError(f"Invalid node type `{node_type:08x}` at "
                ##                 f"offset {offset:08x}")
            node_data = struct.unpack_from(''.join(['<', data_format]),
                                           config_blob, offset)[0]
            offset += struct.calcsize(data_format)

        cfg.nodes.append(ConfigNode(last_offset,
                                    node_id,
                                    node_type,
                                    node_data))
        print(f'NodeId {node_type:08x} at {offset:08x}')
    return cfg



#------------------------------------------------------------------------------
# Everything ShadowCrypto related

class ShadowCrypt:

    @staticmethod
    def imp_crypt_str(encrypted_bytes:bytes):
        """
        Decrypts any import descriptor or API name used by the custom import
        protection. This routine is invoked from the import stub dispatcher
        function.
        """
        # xtract initial value directly from the `encrypted_bytes`
        current_value = int.from_bytes(encrypted_bytes[:4], 'little')

        # output container
        decrypted_bytes = bytearray()

        # Max length, as specified by the initial algo
        max_length = 0x400
        for index in range(max_length):
            # calc next value based on crypt algo
            calculated_value = (17 * current_value - 0x6817FD83) & 0xFFFFFFFF
            value_bytes = calculated_value.to_bytes(4, 'little')

            # sum of the bytes, ensuring it's w/in byte range
            sum_value_bytes = sum(value_bytes) & 0xFF

            # chkif end of the encrypted bytes
            if index + 4 >= len(encrypted_bytes):
                break

            # fetch corresponding encrypted byte by offsetting index
            encrypted_byte = encrypted_bytes[index + 4]

            # decrypt && append
            decrypted_byte = encrypted_byte ^ sum_value_bytes
            decrypted_bytes.append(decrypted_byte)

            # chkif decrypted byte marks the end of sequence
            if encrypted_byte == sum_value_bytes:
                break

            # next cycle
            current_value = calculated_value
        return decrypted_bytes[:-1].decode("ascii")

    @staticmethod
    def transform_cab1071f(data: bytearray,
                       max_buffer_size:int,
                       nonce: list = None):
        input_buffer_size = len(data)
        if input_buffer_size > max_buffer_size:
            return 0x718, None  # corresponds to error code in original logic

        # hardcode in the initial logic
        running_key = 0xcab1071f

        if nonce:
            for value in nonce:
                running_key = (((value + running_key) << 8) +
                               ((value + running_key) >> 24) & 0xFFFFFFFF)

        quotient, remainder = divmod(input_buffer_size, 4)
        data_as_ints = list(int.from_bytes(data[i:i+4], 'little')
                            for i in range(0, quotient * 4, 4))

        for i in range(quotient):
            running_key = (running_key - 0x3ec9f0fc) & 0xFFFFFFFF
            data_as_ints[i] ^= running_key

        if remainder:
            tail_start = quotient * 4
            tail_data = data[tail_start:tail_start+remainder]
            tail_int = int.from_bytes(tail_data, 'little')

            ttail = (running_key - 0x3ec9f0fc) & 0xFFFFFFFF
            ttail ^= tail_int

            for i in range(remainder):
                data[tail_start + i] = (ttail >> (8 * i)) & 0xFF

        for i, int_val in enumerate(data_as_ints):
            data[i*4:(i+1)*4] = int_val.to_bytes(4, 'little')

        return 0, data  # 0 was success in original logic

    @staticmethod
    def transform_6301744a(data: bytearray,
                           max_buffer_size:int,
                           nonce: list = None):
        input_buffer_size = len(data)
        if input_buffer_size > max_buffer_size:
            return 0x718, None  # corresponds to error code in original logic

        # hardcode in the initial logic
        running_key = 0xBB7B610D
        if nonce:
            for value in nonce:
                running_key = (((value + running_key) << 8) +
                               ((value + running_key) >> 24) & 0xFFFFFFFF)

        quotient, remainder = divmod(input_buffer_size, 4)
        data_as_ints = list(int.from_bytes(data[i:i+4], 'little')
                            for i in range(0, quotient * 4, 4))

        for i in range(quotient):
            running_key = (running_key - 0x6301744A) & 0xFFFFFFFF
            data_as_ints[i] ^= running_key

        if remainder:
            tail_start = quotient * 4
            tail_data = data[tail_start:tail_start+remainder]
            tail_int = int.from_bytes(tail_data, 'little')

            ttail = (running_key - 0x6301744A) & 0xFFFFFFFF
            ttail ^= tail_int

            for i in range(remainder):
                data[tail_start + i] = (ttail >> (8 * i)) & 0xFF

        for i, int_val in enumerate(data_as_ints):
            data[i*4:(i+1)*4] = int_val.to_bytes(4, 'little')

        return 0, data  # 0 was success in original logic
#------------------------------------------------------------------------------
def crc_61484215(input_string: bytes,
                 length:int =-1,
                 ignore_case=True):
    """Calculate a custom checksum with a fixed initial seed of 0x61484215.

    :param input_string: The input string to process.
    :param length: The number of characters to process from the input string. 
                   If -1, the entire string is processed.
    :param ignore_case: If True, the function ignores the case
    :return: The calculated CRC32 hash.
    """
    # Constants
    INITIAL_SEED = 0x61484215
    POLYNOMIAL   = 0xDE20980E

    if length == -1:
        length = len(input_string)
    crc = INITIAL_SEED

    for count, char in enumerate(input_string):
        if count >= length:
            break
        ascii_val = ord(char)
        if ignore_case and 'a' <= char <= 'z':
            ascii_val -= 0x20
        crc ^= ascii_val
        for _ in range(8):
            crc = (crc >> 1) ^ (-(crc & 1) & POLYNOMIAL)
    return crc & 0xFFFFFFFF
#------------------------------------------------------------------------------

config_blob = bytearray(open("c:/tmp/sogu-obf/decrypted-config.bin", "rb").read())
config = deserialize_decrypted_config(config_blob, ShadowCrypt.transform_cab1071f)
for node in config.nodes:
    print(node)


### (+0x000004) <Node::01010100> 01000000: `0`
### (+0x000009) <Node::01010200> 01000000: `10`
### (+0x00000e) <Node::06010300> 06000000: `Q9DW9GOCLS11HUHFLYDORPORZALCDDPFB`
### (+0x000038) <Node::06010400> 06000000: `Q9DW9GOCLS11HUHFLYDORPORZALCDDPFB`
### (+0x000062) <Node::06040100> 06000000: `%ProgramFiles%\Marshal\Marshal.exe`
### (+0x00008d) <Node::06040101> 06000000: `%APPDATA%\Marshal\Marshal.exe`
### (+0x0000b3) <Node::06040102> 06000000: `%LOCALAPPDATA%\Marshal\Marshal.exe`
### (+0x0000de) <Node::06040103> 06000000: `%TEMP%\Marshal\Marshal.exe`
### (+0x000101) <Node::06040200> 06000000: ``
### (+0x00010a) <Node::0103f100> 01000000: `0`
### (+0x00010f) <Node::0103f200> 01000000: `0`
### (+0x000114) <Node::0103f300> 01000000: `0`
### (+0x000119) <Node::06030600> 06000000: `Marshal`
### (+0x000129) <Node::06030700> 06000000: `Microsoft\Windows\UPnP`
### (+0x000148) <Node::06030800> 06000000: `Microsoft Corporation`
### (+0x000166) <Node::06030900> 06000000: `Marshal Service to Auto-Remove`
### (+0x00018d) <Node::06030100> 06000000: `Marshal`
### (+0x00019d) <Node::06030200> 06000000: `Marshal Service`
### (+0x0001b5) <Node::06030300> 06000000: `Marshal Service to Auto-Remove`
### (+0x0001dc) <Node::06030400> 06000000: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
### (+0x000212) <Node::06030500> 06000000: `Marshal`
### (+0x000222) <Node::01020100> 01000000: `1`
### (+0x000227) <Node::01020200> 01000000: `1`
### (+0x00022c) <Node::01020300> 01000000: `1`
### (+0x000231) <Node::01020400> 01000000: `0`
### (+0x000236) <Node::01020500> 01000000: `1`  (whether to create outbound firewall rule)
### (+0x00023b) <Node::01020600> 01000000: `1`
### (+0x000240) <Node::01020700> 01000000: `1`
### (+0x000245) <Node::01020800> 01000000: `1`
### (+0x00024a) <Node::06040300> 06000000: `"%PROGRAMFILES%\Windows Mail\WinMail.exe" Marshal`
### (+0x000284) <Node::06040301> 06000000: `"%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe" Marshal`
### (+0x0002c7) <Node::06040302> 06000000: `"%ProgramFiles%\Windows Media Player\wmplayer.exe" Marshal`
### (+0x00030a) <Node::06040303> 06000000: `"%SystemRoot%\system32\svchost.exe" Marshal`
### (+0x00033e) <Node::06040500> 06000000: `SSL://20.89.252.86:443`
### (+0x00035d) <Node::03010600> 03000000: `1`
### (+0x000365) <Node::03010700> 03000000: `a`
### (+0x00036d) <Node::03010800> 03000000: `259`
### (+0x000375) <Node::03010900> 03000000: `26c`
### (+0x00037d) <Node::02050100> 02000000: `0`
### (+0x000383) <Node::02050101> 02000000: `0`
### (+0x000389) <Node::02050102> 02000000: `0`
### (+0x00038f) <Node::02050103> 02000000: `0`
### (+0x000395) <Node::02050300> 02000000: `0`
### (+0x00039b) <Node::02050301> 02000000: `0`
### (+0x0003a1) <Node::02050302> 02000000: `0`
### (+0x0003a7) <Node::02050303> 02000000: `0`
### (+0x0003ad) <Node::06050200> 06000000: ``
### (+0x0003b6) <Node::06050201> 06000000: ``
### (+0x0003bf) <Node::06050202> 06000000: ``
### (+0x0003c8) <Node::06050203> 06000000: ``
### (+0x0003d1) <Node::02050400> 02000000: `0`
### (+0x0003d7) <Node::02050401> 02000000: `0`
### (+0x0003dd) <Node::02050402> 02000000: `0`
### (+0x0003e3) <Node::02050403> 02000000: `0`
### (+0x0003e9) <Node::02050600> 02000000: `0`
### (+0x0003ef) <Node::02050601> 02000000: `0`
### (+0x0003f5) <Node::02050602> 02000000: `0`
### (+0x0003fb) <Node::02050603> 02000000: `0`
### (+0x000401) <Node::06050500> 06000000: ``
### (+0x00040a) <Node::06050501> 06000000: ``
### (+0x000413) <Node::06050502> 06000000: ``
### (+0x00041c) <Node::06050503> 06000000: ``
### (+0x000425) <Node::06040600> 06000000: `HTTP\n\n\n\n\n`
### (+0x000437) <Node::06040601> 06000000: `HTTP\n\n\n\n\n`
### (+0x000449) <Node::06040602> 06000000: `HTTP\n\n\n\n\n`
### (+0x00045b) <Node::06040603> 06000000: `HTTP\n\n\n\n\n`
### (+0x00046d) <Node::03040700> 03000000: `8080808`
### (+0x000475) <Node::03040701> 03000000: `4040808`
### (+0x00047d) <Node::03040702> 03000000: `4040404`
### (+0x000485) <Node::03040703> 03000000: `2020204`
### (+0x00048d) <Node::05010500> 05000000: `bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')`
### (+0x000735) <Node::01040902> 01000000: `0`
### (+0x00073a) <Node::01040903> 01000000: `0`
### (+0x00073f) <Node::06040800> 06000000: `POST`
### (+0x00074c) <Node::06040801> 06000000: `65536`
### (+0x00075a) <Node::06040802> 06000000: `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0`
### (+0x0007bd) <Node::06040803> 06000000: `Accept-Language: en-ca,en;q=0.8,en-us;q=0.6,de-de;q=0.4,de;q=0.2`
### (+0x000806) <Node::06040804> 06000000: `Accept-Encoding: gzip, deflate`
### (+0x00082d) <Node::06040805> 06000000: `Accept: text/html, application/xhtml+xml, image/jxr, */*`
### (+0x00086e) <Node::06040806> 06000000: ``
###
###
###
### url_schemes = [
###         "http://",
###         "https://",
###         "ftp://",
###         "file://",
###         "mailto://",
###         "data://",
###         "tel://",
###         "sms://",
###         "mms://",
###         "rtsp://",
###         "sftp://",
###         "ssh://",
###         "ws://",
###         "wss://",
###         "magnet://",
###         "bitcoin://",
###         "git://",
###         "sip://",
###         "sips://",
###         "ldap://",
###         "gopher://",
###         "ssl://"
### ]
###
###
### class Scanners:
###
###     @staticmethod
###     def find_imptbl_metadata(buffer: bytearray):
###         index = 0
###
###         # The loop continues until there's no more adequate space for the required pattern.
###
###         # The '-5' ensures space for checking the pattern with an offset up to 'index + 5'.
###         while index < len(buffer) - 5:
###             # These conditions try to mimic the checks in the original function.
###             # We're using bitwise XOR (^) operations, similar to the original code, to check for a pattern in the data.
###
###             # In the original C code, it appears there is a comparison being made between the value at the current memory location
###             # and some XOR combination of values at subsequent locations. We attempt to replicate that logic here.
###
###             # Note: We need to handle these indices carefully. If 'index + 5' exceeds the length of buffer,
###             # it would normally cause an error. Our loop's condition prevents this, but be cautious with similar operations.
###
###             condition1 = buffer[index] == (buffer[index + 5] ^ 0x97E8027D)
###             if not condition1:
###                 index += 1  # If the first condition doesn't meet, move to the next byte.
###                 continue
###
###             input(index)
###
###             condition2 = buffer[index] == (buffer[index + 2] ^ 0xF3A300F6)
###             condition3 = buffer[index] == (buffer[index + 3] ^ 0x858AF28D)
###
###             # If all conditions are met, we've found the pattern.
###             if condition1 and condition2 and condition3:
###                 return index  # Or some other appropriate action.
###
###             index += 1  # Move to the next byte in our bytearray.
###
###         return None  # Pattern not found.
###
### # Example of using the function with a hypothetical bytearray.
### # The actual bytearray would need to be obtained or defined based on your specific use case.
###
### # memory = bytearray(...)  # This should be your actual bytearray of data.
### # result = find_pattern(memory)
###
### # if result is not None:
### #     print(f"Pattern found at index {result}")
### # else:
### #     print("Pattern not found.")
###
###
### _DWORD *sub_140001510() {
###   v0 = retaddr;
###   do {
###     do {
###       v1 = *(_DWORD *)((char *)v0 + 5);
###       v0 = (_DWORD *)((char *)v0 + 1);
###     } while ( *v0 != (v1 ^ 0x97E8027D) );
###   } while ( *v0 != (v0[2] ^ 0xF3A300F6) || *v0 != (v0[3] ^ 0x858AF28D) );
###   return v0;
### }
###
###
### def sub_140001510(buffer: bytearray):
###     index = 0  # Represents the current position in the bytearray.
###     memory_size = len(buffer)
###
###     # We continue until there's no more adequate space for the required pattern.
###     while index < memory_size - 20:  # Ensure there's enough space for the pattern with offsets.
###
###         # Equivalent to *(_DWORD *)((char *)v0 + 5);
###         v1 = int.from_bytes(buffer[index + 5:index + 9], byteorder='little')
###
###         # Equivalent to *v0 in the conditions below. Extracting 4 bytes as a single integer (DWORD).
###         v0_value = int.from_bytes(buffer[index:index + 4], byteorder='little')
###
###         condition1 = v0_value == (v1 ^ 0x97E8027D)
###         if not condition1:
###             index += 4  # If the first condition doesn't meet, move by 4 bytes (size of DWORD).
###             continue
###
###         input('inio')
###
###         # Additional conditions are checked only if the first condition is met.
###         # These are relative to the current position, so we're using 'index' for the position.
###         condition2 = v0_value == (int.from_bytes(buffer[index + 8:index + 12], byteorder='little') ^ 0xF3A300F6)
###         condition3 = v0_value == (int.from_bytes(buffer[index + 12:index + 16], byteorder='little') ^ 0x858AF28D)
###
###         # If all conditions are met, we've found the pattern.
###         if condition1 and condition2 and condition3:
###             return index  # Or some other appropriate action, like returning a slice of the bytearray.
###
###         index += 4  # Move to the next DWORD in our bytearray.
###
###     return None  # Pattern not found.
###
### # Usage example:
### # memory = bytearray(...)  # This should be your actual bytearray of data.
### # result = sub_140001510(memory)
###
### # if result is not None:
### #     print(f"Pattern found at index {result}")
### # else:
### #     print("Pattern not found.")
###
###
### (+0x000004) <Node::01010100> 01000000: `0`,
### (+0x000009) <Node::01010200> 01000000: `10`,
### (+0x00000e) <Node::06010300> 06000000: `Q9DW9GOCLS11HUHFLYDORPORZALCDDPFB`,
### (+0x000038) <Node::06010400> 06000000: `Q9DW9GOCLS11HUHFLYDORPORZALCDDPFB`,
### (+0x000062) <Node::06040100> 06000000: `%ProgramFiles%\Marshal\Marshal.exe`,
### (+0x00008d) <Node::06040101> 06000000: `%APPDATA%\Marshal\Marshal.exe`,
### (+0x0000b3) <Node::06040102> 06000000: `%LOCALAPPDATA%\Marshal\Marshal.exe`,
### (+0x0000de) <Node::06040103> 06000000: `%TEMP%\Marshal\Marshal.exe`,
### (+0x000101) <Node::06040200> 06000000: ``,
### (+0x00010a) <Node::0103f100> 01000000: `0`,
### (+0x00010f) <Node::0103f200> 01000000: `0`,
### (+0x000114) <Node::0103f300> 01000000: `0`,
### (+0x000119) <Node::06030600> 06000000: `Marshal`,
### (+0x000129) <Node::06030700> 06000000: `Microsoft\Windows\UPnP`,
### (+0x000148) <Node::06030800> 06000000: `Microsoft Corporation`,
### (+0x000166) <Node::06030900> 06000000: `Marshal Service to Auto-Remove`,
### (+0x00018d) <Node::06030100> 06000000: `Marshal`,
### (+0x00019d) <Node::06030200> 06000000: `Marshal Service`,
### (+0x0001b5) <Node::06030300> 06000000: `Marshal Service to Auto-Remove`,
### (+0x0001dc) <Node::06030400> 06000000: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
### (+0x000212) <Node::06030500> 06000000: `Marshal`,
### (+0x000222) <Node::01020100> 01000000: `1`,
### (+0x000227) <Node::01020200> 01000000: `1`,
### (+0x00022c) <Node::01020300> 01000000: `1`,
### (+0x000231) <Node::01020400> 01000000: `0`,
### (+0x000236) <Node::01020500> 01000000: `1`,
### (+0x00023b) <Node::01020600> 01000000: `1`,
### (+0x000240) <Node::01020700> 01000000: `1`
### (+0x000245) <Node::01020800> 01000000: `1`,
### (+0x00024a) <Node::06040300> 06000000: `"%PROGRAMFILES%\Windows Mail\WinMail.exe" Marshal`,
### (+0x000284) <Node::06040301> 06000000: `"%PROGRAMFILES%\Windows Media Player\wmpnetwk.exe" Marshal`,
### (+0x0002c7) <Node::06040302> 06000000: `"%ProgramFiles%\Windows Media
### Player\wmplayer.exe" Marshal`,
### (+0x00030a) <Node::06040303> 06000000: `"%SystemRoot%\system32\svchost.exe" Marshal`,
### (+0x00033e) <Node::06040500> 06000000: `SSL://20.89.252.86:443`,
### (+0x00035d) <Node::03010600> 03000000: `1`,
### (+0x000365) <Node::03010700> 03000000: `a`,
### (+0x00036d) <Node::03010800> 03000000: `25a`,
### (+0x000375) <Node::03010900> 03000000: `26d`,
### (+0x00037d) <Node::02050100> 02000000: `0`,
### (+0x000383) <Node::02050101> 02000000: `0`,
### (+0x000389) <Node::02050102> 02000000: `0`,
### (+0x00038f) <Node::02050103> 02000000: `0`,
### (+0x000395) <Node::02050300> 02000000: `0`,
### (+0x00039b) <Node::02050301> 02000000: `0`,
### (+0x0003a1) <Node::02050302> 02000000: `0`,
### (+0x0003a7) <Node::02050303> 02000000: `0`,
### (+0x0003ad) <Node::06050200> 06000000: ``,
### (+0x0003b6) <Node::06050201> 06000000: ``,
### (+0x0003bf) <Node::06050202> 06000000: ``,
### (+0x0003c8) <Node::06050203> 06000000: ``,
### (+0x0003d1) <Node::02050400> 02000000: `0`,
### (+0x0003d7) <Node::02050401> 02000000: `0`,
### (+0x0003dd) <Node::02050402> 02000000: `0`,
### (+0x0003e3) <Node::02050403> 02000000: `0`,
### (+0x0003e9) <Node::02050600> 02000000: `0`,
### (+0x0003ef) <Node::02050601> 02000000: `0`,
### (+0x0003f5) <Node::02050602> 02000000: `0`,
### (+0x0003fb) <Node::02050603> 02000000: `0`,
### (+0x000401) <Node::06050500> 06000000: ``,
### (+0x00040a) <Node::06050501> 06000000: ``,
### (+0x000413) <Node::06050502> 06000000: ``,
### (+0x00041c) <Node::06050503> 06000000: ``,
### (+0x000425) <Node::06040600> 06000000: 00 06 04
### `HTTP
### 172.25.82.140
### 81
###
###
### `, (+0x000446) <Node::06040601> 06000000: `HTTP
###
###
###
###
### `, (+0x000458) <Node::06040602> 06000000: `HTTP
###
###
###
###
### `, (+0x00046a) <Node::06040603> 06000000: `HTTP
###
###
###
###
### `,
### (+0x00047c) <Node::03040700> 03000000: `8080808`,
### (+0x000484) <Node::03040701> 03000000: `4040808`,
### (+0x00048c) <Node::03040702> 03000000: `4040404`,
### (+0x000494) <Node::03040703> 03000000: `2020204`,
### (+0x00049c) <Node::05010500> 05000000: `bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')`,
### (+0x000744) <Node::01040902> 01000000: `0`,
### (+0x000749) <Node::01040903> 01000000: `0`,
### (+0x00074e) <Node::06040800> 06000000: `POST`,
### (+0x00075b) <Node::06040801> 06000000: `65536`,
### (+0x000769) <Node::06040802> 06000000: `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64;
### x64; rv:87.0) Gecko/20100101 Firefox/87.0`,
### (+0x0007cc) <Node::06040803> 06000000: `Accept-Language: en-ca,en;q=0.8,en-us;q=0.6,de-de;q=0.4,de;q=0.2`,
### (+0x000815) <Node::06040804> 06000000: `Accept-Encoding: gzip, deflate`,
### (+0x00083c) <Node::06040805> 06000000: `Accept: text/html, application/xhtml+xml, image/jxr, */*`,
### (+0x00087d) <Node::06040806> 06000000: ``
###
###
###
###
###

def custom_stream_cipher_cab1071f(
    data: bytearray,
    max_buffer_size:int,
    nonce: list = [0x7B, 0xDC, 0x17, 0xFE]):   # the last 4-bytes of the encrypted buffer
    input_buffer_size = len(data)
    if input_buffer_size > max_buffer_size:
        return 0x718, None

    running_key = 0xcab1071f
    if nonce:
        for value in nonce:
            running_key = (((value + running_key) << 8) +
                           ((value + running_key) >> 24) & 0xFFFFFFFF)

    quotient, remainder = divmod(input_buffer_size, 4)
    data_as_ints = list(int.from_bytes(data[i:i+4], 'little')
                        for i in range(0, quotient * 4, 4))

    for i in range(quotient):
        running_key = (running_key - 0x3ec9f0fc) & 0xFFFFFFFF
        data_as_ints[i] ^= running_key

    if remainder:
        tail_start = quotient * 4
        tail_data = data[tail_start:tail_start+remainder]
        tail_int = int.from_bytes(tail_data, 'little')

        ttail = (running_key - 0x3ec9f0fc) & 0xFFFFFFFF
        ttail ^= tail_int

        for i in range(remainder):
            data[tail_start + i] = (ttail >> (8 * i)) & 0xFF

    for i, int_val in enumerate(data_as_ints):
        data[i*4:(i+1)*4] = int_val.to_bytes(4, 'little')

    return 0, data  # 0 was success in original logic