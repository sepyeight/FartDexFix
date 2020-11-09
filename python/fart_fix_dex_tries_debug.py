# https://formats.kaitai.io/vlq_base128_le/python.html
# https://github.com/kaitai-io/kaitai_struct/issues/439
# https://formats.kaitai.io/dex/python.html
# https://github.com/gagalin95/FART_repairdex/blob/master/repairdex.py
# 把抽取的代码中的trysize改成0了
# python fart_fix_dex_tries_debug.py -d 11740_dexfile.dex -b 11740_ins_5455.bin > test01.log
# python fart_fix_dex_tries_debug.py -d 755064_dexfile.dex -b 755064_ins_5455.bin > test01.log
# python fart_fix_dex_tries_debug.py -d 1833604_dexfile.dex -b 1833604_ins_5455.bin > test01.log
# python fart_fix_dex_tries_debug.py -d 10422820_dexfile.dex -b 10422820_ins_5455.bin > test01.log
# python fart_fix_dex_tries_debug.py -d 11902988_dexfile.dex -b 11902988_ins_5455.bin > test01.log
#

from dex import Dex
import optparse
import sys
import re
import base64
import binascii


def args_check():
    parser = optparse.OptionParser()
    parser.add_option('-d',
                      '--dex',
                      action='store',
                      dest='dex_file_path',
                      help='dex file path',
                      default='')
    parser.add_option('-b',
                      '--bin',
                      action='store',
                      dest='bin_file_path',
                      help='bin file path',
                      default='')
    return parser.parse_args()


def bin_init(bin_file_path):
    with open(bin_file_path, 'r') as file:
        bin_file = file.read()
    inists = bin_file.split(';')
    dex_bin_codes = {}
    for inis in inists:
        if inis != '':
            method_index = re.search(r'method_idx:(\d*)', inis).group(1)
            inis_code_len = re.search(r'code_item_len:(\d*)', inis).group(1)
            inis_code = re.search(r'ins:(\S*)}', inis).group(1)
            dex_bin_codes[method_index] = inis_code_len + ':' + inis_code
    # print("origin info", dex_bin_codes)
    return dex_bin_codes


def fix_dex(dex_file_path, dex_bin_codes):
    dex_file = open(dex_file_path, 'rb+')
    dex = Dex.from_bytes(dex_file.read())

    class_defs = dex.class_defs
    for class_def in class_defs:
        # print('class def info', class_def.type_name)
        class_data = class_def.class_data
        if class_data is not None:
            virtual_method_index = 0
            # print('\tvitual method code length =', len(class_data.virtual_methods))
            for x in range(len(class_data.virtual_methods)):
                if x == 0:
                    virtual_method_index = class_data.virtual_methods[
                        x].method_idx_diff.value
                else:
                    virtual_method_index += class_data.virtual_methods[
                        x].method_idx_diff.value
                virtual_method_code_offset = class_data.virtual_methods[
                    x].code_off.value

                #
                inis_code_info = dex_bin_codes.get(str(virtual_method_index))
                if inis_code_info is not None:
                    inis_code_info = inis_code_info.split(':')
                    inis_code_len = inis_code_info[0]
                    inis_code = base64.b64decode(inis_code_info[1].encode())
                    dex_file.seek(virtual_method_code_offset, 0)
                    orig_inis_code = dex_file.read(int(inis_code_len))
                    orig_inis_code_hex = binascii.b2a_hex(orig_inis_code).decode('utf-8')
                    inis_code_hex = binascii.b2a_hex(inis_code).decode('utf-8')
                    print("virtual_method orig inis code:", orig_inis_code_hex, ", inis code:", inis_code_hex, ", is same:",
                          'yes' if orig_inis_code_hex[32:] == inis_code_hex[32:] else 'no')
                    if orig_inis_code_hex[32:] != inis_code_hex[32:]:
                        seek_to = virtual_method_code_offset + 6
                        dex_file.seek(seek_to, 0)
                        dex_file.write(b'\x00')
                        inis_code = inis_code[8:]
                        seek_to = seek_to + 2
                        dex_file.seek(seek_to, 0)
                        dex_file.write(inis_code)
                        dex_file.flush()

                        dex_file.seek(virtual_method_code_offset, 0)
                        modify_inis_code = dex_file.read(int(inis_code_len))
                        print('virtual_method modify is same', 'yes' if binascii.hexlify(modify_inis_code)[32:] == inis_code_hex[32:] else 'no')
            direct_method_index = 0
            # print('\tdirect method code length =', len(class_data.direct_methods))
            for x in range(len(class_data.direct_methods)):
                if x == 0:
                    direct_method_index = class_data.direct_methods[
                        x].method_idx_diff.value
                else:
                    direct_method_index += class_data.direct_methods[
                        x].method_idx_diff.value
                direct_method_code_offset = class_data.direct_methods[
                    x].code_off.value
                #

                inis_code_info = dex_bin_codes.get(str(direct_method_index))
                if inis_code_info is not None:
                    inis_code_info = inis_code_info.split(':')
                    inis_code_len = inis_code_info[0]
                    inis_code = base64.b64decode(inis_code_info[1].encode())
                    dex_file.seek(direct_method_code_offset, 0)
                    orig_inis_code = dex_file.read(int(inis_code_len))
                    orig_inis_code_hex = binascii.b2a_hex(orig_inis_code).decode('utf-8')
                    inis_code_hex = binascii.b2a_hex(inis_code).decode('utf-8')
                    print("direct_method orig inis code:", orig_inis_code_hex, ", inis code:", inis_code_hex,
                          ", is same:",
                          'yes' if orig_inis_code_hex[32:] == inis_code_hex[32:] else 'no')
                    if orig_inis_code_hex[32:] != inis_code_hex[32:]:
                        seek_to = direct_method_code_offset + 6
                        dex_file.seek(seek_to, 0)
                        dex_file.write(b'\x00')
                        inis_code = inis_code[8:]
                        seek_to = seek_to + 2
                        dex_file.seek(seek_to, 0)
                        dex_file.write(inis_code)
                        dex_file.flush()

                        dex_file.seek(direct_method_code_offset, 0)
                        modify_inis_code = dex_file.read(int(inis_code_len))
                        print('direct_method modify is same',
                              'yes' if binascii.hexlify(modify_inis_code)[32:] == inis_code_hex[32:] else 'no')
    dex_file.close()


if __name__ == '__main__':
    options, _ = args_check()
    if options.dex_file_path == '' or options.bin_file_path == '':
        print('Usage:')
        print('\tpython3 fart_fix_dex.py -d dex_file_path -b bin_file_path')
    else:
        dex_file_path = options.dex_file_path
        bin_file_path = options.bin_file_path
        dex_bin_codes = bin_init(bin_file_path)
        fix_dex(dex_file_path, dex_bin_codes)
