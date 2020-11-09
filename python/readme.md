# fart脱壳后修复

用过fart的大佬都知道，拖出来的dex文件一般是需要修复一下的...

好久没有脱壳了，最近遇到一个apk需要脱壳，于是偷懒使用大神编译好的镜像刷入手机，脱壳一切顺利，上网搜了几个fart.py修复...

拖进jadx，喝口水，开始分析代码：

我看到了这些：

```bash
255efc: 0000                |0000: nop // spacer
255efe: 14004b1f003c        |0001: const v0, #int 0x3c001f4b
255f04: 0000                |0004: nop // spacer
255f06: 0000                |0005: nop // spacer
255f08: 0000                |0006: nop // spacer
255f0a: 0000                |0007: nop // spacer
255f0c: 0000                |0008: nop // spacer
255f0e: 0000                |0009: nop // spacer
255f10: 0000                |000a: nop // spacer
255f12: 0000                |000b: nop // spacer
255f14: 0000                |000c: nop // spacer
255f16: 0000                |000d: nop // spacer
255f18: 0000                |000e: nop // spacer
255f1a: 0000                |000f: nop // spacer
255f1c: 0000                |0010: nop // spacer
255f1e: 0000                |0011: nop // spacer
255f20: 1200                |0012: const/4 v0, #int 0 // #0
255f22: 0f00                |0013: return v0

.catches(1 try-catch)

  .try[0013->0014]
   catch(Ljava/lang/Exception;)->handler(0000)

.endmethod
```

于是我又修复了一边，然后，还是老样子...，此时我一脸懵逼！！！

到底哪里出现了问题？？？

难道加固又升级了吗，还是方法的inis没有拖出来，让我来打开bin文件看看

## 开始研究

打开bin文件，随便找一条拖出来的ins看看是不是没有成功拖出来

```bash
{name:void com.*.AccountLockActivity$1.<init>(com.*.AccountLockActivity, android.app.Activity, boolean, java.lang.String),method_idx:2013,offset:5953880,code_item_len:28,ins:BQAFAAQAAAAUV5wABgAAAFsB/gBwQLshIEMOAA==}
```

解出来

```bash
050005000400000014579c00060000005b01fe007040bb2120430e00
```

然后手动贴到dex文件对应的偏移中，使用jadx打开正常了。

就是dex修复的python有问题了...

准备下载hanbing大佬的python看看，代码太复杂被劝退了，于是在github上冲浪了好久，发现了几个简单的脚本，研究了一下，发现就是简单的读取`offset`，然后把`inis`解码后写进去就好了，原理很简单，为什么就没修复正确呢？

## 我们再来看看bin文件

重新观察一下bin文件

```bash
{name:void com.*.onError(java.lang.Throwable),method_idx:2014,offset:-1658796796,code_item_len:73,ins:BgACAAEAAQAAAAAAFgAAABIwIwCsJBIBTQQAARIRTQUAARIhEwNNAHEQPJEDAAwCTQIAAXEQggYAAA4AFQAAAAEAAQABAfosAA==}
```

这个的`offset`是负值，应该就是这个问题了

现在怎么办呢？拖出来的方法信息包括：

```bash
name， method_idx, offset, code_item_len, ins
```

似乎只能通过`method_idx`来确定了，打开一个正确的dex，先看看encoded_method：

| 名称            | 格式    | 说明                                                         |
| --------------- | ------- | ------------------------------------------------------------ |
| method_idx_diff | uleb128 | 此方法标识（包括名称和描述符）的 `method_ids` 列表中的索引；它会表示为与列表中前一个元素的索引之间的差值。列表中第一个元素的索引则直接表示出来。 |
| access_flags    | uleb128 | 方法的访问标记（`public`、`final`等）。如需了解详情，请参阅“`access_flags` 定义”。 |
| code_off        | uleb128 | 从文件开头到此方法的代码结构的偏移量；如果此方法是 `abstract` 或 `native`，则该值为 `0`。偏移量应该是到 `data` 区段中某个位置的偏移量。数据格式由下文的“`code_item`”指定。 |

可以通过`method_idx_diff`属性值的叠加计算出`method_idx`，尝试读取原始dex的`code_off`来获取正确的偏移，然后完成修复。

## 写代码

第一个问题，是否有python版本的dex文件结构解析脚本...

通过google终于找到了，感谢`kaitaistruct`

```python
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

import vlq_base128_le
class Dex(KaitaiStruct):
    """Android OS applications executables are typically stored in its own
    format, optimized for more efficient execution in Dalvik virtual
    machine.
    
    This format is loosely similar to Java .class file format and
    generally holds the similar set of data: i.e. classes, methods,
    fields, annotations, etc.
    
    .. seealso::
       Source - https://source.android.com/devices/tech/dalvik/dex-format
    """

```

顺便找到了uleb128的解析python脚本

```python
# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class VlqBase128Le(KaitaiStruct):
    """A variable-length unsigned integer using base128 encoding. 1-byte groups
    consist of 1-bit flag of continuation and 7-bit value chunk, and are ordered
    "least significant group first", i.e. in "little-endian" manner.
    
    This particular encoding is specified and used in:
    
    * DWARF debug file format, where it's dubbed "unsigned LEB128" or "ULEB128".
      http://dwarfstd.org/doc/dwarf-2.0.0.pdf - page 139
    * Google Protocol Buffers, where it's called "Base 128 Varints".
      https://developers.google.com/protocol-buffers/docs/encoding?csw=1#varints
    * Apache Lucene, where it's called "VInt"
      http://lucene.apache.org/core/3_5_0/fileformats.html#VInt
    * Apache Avro uses this as a basis for integer encoding, adding ZigZag on
      top of it for signed ints
      http://avro.apache.org/docs/current/spec.html#binary_encode_primitive
    
    More information on this encoding is available at https://en.wikipedia.org/wiki/LEB128
    
    This particular implementation supports serialized values to up 8 bytes long.
    """

```

下来就是解析修复dex了

```python
# https://formats.kaitai.io/vlq_base128_le/python.html
# https://github.com/kaitai-io/kaitai_struct/issues/439
# https://formats.kaitai.io/dex/python.html
# https://github.com/gagalin95/FART_repairdex/blob/master/repairdex.py
# python fart_fix_dex.py -d 11902988_dexfile.dex -b 11902988_ins_5455.bin

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
    '''
    参数检查
    '''
    with open(bin_file_path, 'r') as file:
        bin_file = file.read()
    inists = bin_file.split(';')
    dex_bin_codes = {}
    for inis in inists:
        if inis != '':
            method_index = re.search(r'method_idx:(\d*)', inis).group(1)
            inis_code = re.search(r'ins:(\S*)}', inis).group(1)
            dex_bin_codes[method_index] = inis_code
    # print("origin info", dex_bin_codes)
    return dex_bin_codes


def fix_dex(dex_file_path, dex_bin_codes):
    '''
    修复dex
    '''
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
                inis_code = dex_bin_codes.get(str(virtual_method_index))
                # 在实际测试中发现有可能需要修复triessize和debug
                if inis_code is not None:
                    dex_file.seek(virtual_method_code_offset, 0)
                    inis_code = base64.b64decode(inis_code.encode())
                    dex_file.write(inis_code)
                    dex_file.flush()
                # print('\tvirtual method code index:', virtual_method_index)
                # print('\tvirtual method code offset:',
                #       virtual_method_code_offset)

                # print('\tvirtual method inins:', binascii.b2a_hex(iniscode).decode())
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

                inis_code = dex_bin_codes.get(str(direct_method_index))
                if inis_code is not None:
                    # print('Yes')
                    dex_file.seek(direct_method_code_offset, 0)
                    inis_code = base64.b64decode(inis_code.encode())
                    dex_file.write(inis_code)
                    dex_file.flush()
                # print('\tvirtual method code index:', direct_method_index)
                # print('\tvirtual method code offset:',
                #       direct_method_code_offset)
                # print('\tdirect method inins:', binascii.b2a_hex(iniscode).decode())
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
```

到这里就结束了，就可以尝试修复dex文件了

## windows下安装使用

### 安装`kaitaistruct`

```bash
pip install --upgrade git+https://github.com/kaitai-io/kaitai_struct_python_runtime.git
```
### 使用

```bash
python fart_fix_dex.py -d dexfile -b binfile
```

## Android下的修复app

实现了一个Android版本的修复dex的app，基本原理与python版本一致，再次感谢`KaitaiStruct`，让我们有了java版本的dex文件解析方法。