import ida_bytes
import ida_idaapi
import ida_loader
import idaapi
import struct
import ida_search
import idc
import idautils
import ida_funcs


start_ea = idaapi.get_imagebase()
end_ea = idaapi.get_inf_structure().max_ea
is_64bit = idaapi.get_inf_structure().is_64bit()


# 验证大小端
info = idaapi.get_inf_structure()
try:
    is_be = info.is_be()
except:
    is_be = info.mf
v12magic = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"
v116magic = "FF FF FF FA 00 00" if is_be else "FA FF FF FF 00 00"
v118magic = "FF FF FF F0 00 00" if is_be else "F0 FF FF FF 00 00"
v120magic = "FF FF FF F1 00 00" if is_be else "F1 FF FF FF 00 00"

# 输出
DEBUG = False
def info(formatted_string):
    print("[info] " + formatted_string)

def error(formatted_string):
    print('[ERROR] %s' % formatted_string)

def debug(formatted_string):
    if DEBUG:
        print('[DEBUG] %s' % formatted_string)


def find_pcHeader_without_magic(textStartflag):
    
    if textStartflag:    info("Scanning for pcHeader between 0x%X and 0x%X" % (start_ea, end_ea))
    else:  info("Fuzzy scanning for pcHeader between 0x%X and 0x%X" % (start_ea, end_ea))

    # 根据架构，确定指针大小

    if is_64bit:
        ptr_size = 8
        ptr_format = 'Q'  # unsigned long long (8 bytes)
        int_format = 'q'  # signed long long (8 bytes)
    else:
        ptr_size = 4
        ptr_format = 'I'  # unsigned int (4 bytes)
        int_format = 'i'  # signed int (4 bytes)

    # pcHeader 结构的格式
    # uint32 magic          (4 bytes)
    # uint8 pad1            (1 byte)
    # uint8 pad2            (1 byte)
    # uint8 minLC           (1 byte)
    # uint8 ptrSize         (1 byte)
    # int nfunc             (4 bytes in 32-bit, 8 bytes in 64-bit)
    # uint nfiles           (4 bytes in 32-bit, 8 bytes in 64-bit)
    # uintptr textStart     (4 bytes in 32-bit, 8 bytes in 64-bit)
    # uintptr funcnameOffset
    # uintptr cuOffset
    # uintptr filetabOffset
    # uintptr pctabOffset
    # uintptr pclnOffset

    # 计算需要的填充字节数，以确保 nfunc 对齐
    if is_64bit:
        padding = ''
        pc_header_format = '<I2B2B' + padding + int_format + 'Q' + ptr_format * 6
    else:
        pc_header_format = '<I2B2B' + int_format + 'I' + ptr_format * 6

    pc_header_size = struct.calcsize(pc_header_format)

    # 遍历整个二进制文件
    ea = start_ea
    while ea + pc_header_size < end_ea:
        data = ida_bytes.get_bytes(ea, pc_header_size)
        if not data or len(data) < pc_header_size:
            ea += 1
            continue

        fields = struct.unpack(pc_header_format, data)

        pcHeader = {
            'magic':          fields[0],
            'pad1':           fields[1],
            'pad2':           fields[2],
            'minLC':          fields[3],
            'ptrSize':        fields[4],
            'nfunc':          fields[5],
            'nfiles':         fields[6],
            'textStart':      fields[7],
            'funcnameOffset': fields[8],
            'cuOffset':       fields[9],
            'filetabOffset':  fields[10],
            'pctabOffset':    fields[11],
            'pclnOffset':     fields[12],
        }

        # 验证字段的合理性
        status = validate_pcHeader(pcHeader, ea, textStartflag=textStartflag)
        if status:
            info("Possible pcHeader found at 0x%X" % ea)
            for key, value in pcHeader.items():
                if isinstance(value, int):
                    print(f"  {key}: {value} (0x{value:X})")
                else:
                    print(f"  {key}: {value}")
                    
            # 如果需要，可以返回或记录找到的 pcHeader 位置
            return ea, pcHeader

        ea += 1  # 逐字节移动，继续搜索

    error("Failed to find pcHeader without relying on magic value.")
    return None, None

def validate_pcHeader(pcHeader, ea, textStartflag):

    # 验证 magic 字段，应为 0xFFFFFFF1
    # if pcHeader['magic'] != 0xFFFFFFF1:
    #     return False

    # 验证 pad1 和 pad2，一般为 0
    if pcHeader['pad1'] != 0 or pcHeader['pad2'] != 0:
        return False

    # 验证 minLC，一般为 1、2 或 4
    if pcHeader['minLC'] not in (1, 2, 4):
        return False

    # 验证 ptrSize，应为 4 或 8
    if pcHeader['ptrSize'] not in (4, 8):
        return False

    # 验证 nfunc，为正整数，且不过大
    if pcHeader['nfunc'] <= 0 or pcHeader['nfunc'] > 100000:
        return False

    # 验证 nfiles，为非负整数，且不过大
    if pcHeader['nfiles'] <= 0 or pcHeader['nfiles'] > 100000:
        return False

    # 验证偏移量字段，应为正整数，且不过大
    offset_fields = ['funcnameOffset', 'cuOffset', 'filetabOffset', 'pctabOffset', 'pclnOffset']
    
    for field in offset_fields:
        value = pcHeader[field]
        if value <= 0 or value > (0xFFFFFFFFFFFFFFFF if is_64bit else 0xFFFFFFFF):
            return False

    # 验证偏移量是否在合理范围内
    for field in offset_fields:
        value = pcHeader[field]
        offset_addr = ea + value
        if not ea <= offset_addr <= idaapi.get_inf_structure().max_ea:
            return False
            
    # 验证 textStart，应在合法的地址范围内（模糊匹配）
    textStart = pcHeader['textStart']
    if textStartflag:
        if not start_ea <= textStart <= end_ea:
            return False

    return True
    
def recreate_pclntab(ea):
    if is_64bit:
        get_content = idc.get_qword
        multiplier = 8
    else:
        get_content = ida_bytes.get_dword
        multiplier = 4
    
    exists = False
    for seg in idautils.Segments():
        name = idaapi.get_segm_name(idaapi.getseg(seg))
        if "gopclntab" in name:
            exists = True
            info("GoPCLNTab Found: %s" % name)
            break    
    halt = False
    empty_counter = 0
    seg_start = ea
    while (not halt):
        if empty_counter >= 3:
            seg_end = ea
            info("Effective .gopclntab seg_end: %s" % str(hex(seg_end)))
            halt = True
        offset_addr = get_content(ea)
        if offset_addr == 0:
            empty_counter += 1
            continue
        func_name = idc.get_func_name(offset_addr)
        if func_name == "":
            ida_bytes.del_items(offset_addr)
            idc.create_insn(offset_addr)
            ida_funcs.add_func(offset_addr)
        ea = ea + multiplier

    if not exists:
        if seg_end > seg_start:
            print("[info] Creating .gopclntab: ", hex(seg_start), hex(seg_end))
            idaapi.add_segm(0, seg_start, seg_end, ".gopclntab", "DATA")


def find_magic(magic):
    ea = ida_search.find_binary(start_ea, end_ea, magic, 16, ida_search.SEARCH_DOWN)
    if ea == idaapi.BADADDR:
        return idaapi.BADADDR
    pc, ptr = idc.get_bytes(ea + 6, 2)
    if pc not in [1,2,4]:
        return idaapi.BADADDR
    if ptr not in [4,8]:
        return idaapi.BADADDR
    return ea
    
    
def main1():

    info("Parsing using a generic method")

    ea = find_magic(v12magic)
    if ea == idaapi.BADADDR:
        ea = find_magic(v116magic)

    if ea == idaapi.BADADDR:
        ea = find_magic(v118magic)

    if ea == idaapi.BADADDR:
        ea = find_magic(v120magic)
        
    if ea == idaapi.BADADDR:
        error("Cannot use generic methods for parsing")
        info("Parsing using structure traversal")
        pcHeader_ea, pcHeader = find_pcHeader_without_magic(textStartflag=True)
        if pcHeader:
            recreate_pclntab(pcHeader_ea)
        else:
            error("Cannot use structure traversal to parse")
            info("Parsing using structure traversal")
            pcHeader_ea, pcHeader = find_pcHeader_without_magic(textStartflag=False)
            if pcHeader:
                recreate_pclntab(pcHeader_ea)
            else:
                error("pcHeader not found.")
    else:
        recreate_pclntab(ea)
        


if __name__ == "__main__":
    main1()    

