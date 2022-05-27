import argparse

import gdb

import pwndbg.color
import pwndbg.commands
import pwndbg.dt
import pwndbg.enhance
import pwndbg.memory
import pwndbg.symbol
import pwndbg.typeinfo
import pwndbg.vmmap
import pwndbg.search

import struct
import time

def is_mapped(address, pages, skip_stack=True):
    for page in pages:
        if skip_stack and page.is_stack:
            continue
        if address in page:
            return True
    return False



parser = argparse.ArgumentParser()
parser.description = """
    Find a stack entry that can reach an address by deep indirection.
    """
parser.add_argument("address", type=int, default=0, help="The address to reach")
parser.add_argument("skip", type=str, nargs='?', default=None, help="Comma-separated page to skip, e.g. '0x123,0x456'")
parser.add_argument("max_depth", type=int, nargs='?', default=16, help="Depth limit of the indirection chain")
parser.add_argument("max_lookback", type=int, nargs='?', default=256, help="Max number of qwords to look behind")
@pwndbg.commands.ArgparsedCommand(parser)
def findptr(address=None, skip=None, max_depth=16, max_lookback=256):
    """
    Findptr
    """

    address = int(address)
    skip_pages = []

    if skip is not None:
        for start in skip.split(","):
            skip_pages.append(int(start, 0))

    pages = pwndbg.vmmap.get()

    # Extract the maps we care about
    mappings = []
    mapped_mem_size = 0
    for page in pages:
        if not ('[heap' in page.objfile or '[anon' in page.objfile):
            continue
        if int(page.vaddr) in skip_pages:
            continue
        mappings.append(page)
        mapped_mem_size += page.memsz
    print(f"{mapped_mem_size=} bytes")

    # Find the stack page
    for page in pages:
        if page.is_stack:
            stack = page
            break

    assert(stack is not None)
    stack_start = stack.vaddr
    stack_size = stack.memsz

    # Read the whole stack into a map of {value:[addresses]}
    stack_bytes = pwndbg.memory.read(stack_start, stack_size)
    stack_uint64 = list(struct.unpack(f"<{stack_size // 8}Q", stack_bytes))
    stack_data_to_addr = {}
    for i, val in enumerate(stack_uint64):
        addr = stack.vaddr + i * 8
        if val in stack_data_to_addr:
            stack_data_to_addr[val].append(addr)
        else:
            stack_data_to_addr[val] = [addr]


    def find_in_ram(value):
        return list(pwndbg.search.search(struct.pack("<Q", value),
                                         mappings=mappings,
                                         executable=False,
                                         writable=False))


    def find_in_stack(value):
        if value in stack_data_to_addr:
            return stack_data_to_addr[value]
        else:
            return None


    def recurse(addr, history, path, dig=True, offset=0):
        if len(history) > max_depth:
            return None
        if not is_mapped(addr, pages):
            return None
        if addr in history:
            return None

        history.append(addr)

        stack_ptrs = find_in_stack(addr)
        if stack_ptrs is not None:
            print("WIN condition:")
            for a in stack_ptrs:
                print(f"  0x{a:x}")
            return (stack_ptrs, history, path)

        # t0 = time.time()
        addresses = find_in_ram(addr)
        # print(time.time() - t0)

        if len(addresses) > 0:
            for a in addresses:
                print(f"  found 0x{a:x} => 0x{addr:x}")
                if offset > 0:
                    path.append((addr, offset))
                path.append((addr, 0))
                ret = recurse(a, history.copy(), path.copy())
                if ret is not None:
                    return ret
        elif dig:
            for x in range(max_lookback):
                ret = recurse(addr - 8*x, history.copy(), path.copy(), False, 8 * x)
                if ret is not None:
                    return ret

        return None


    history = []
    path = []
    out = recurse(address, history, path)
    if out is not None:
        found_addr, history_out, path_out = out
        for a in found_addr:
            print(f"Found address: 0x{a:x} ($rsp - {hex(pwndbg.regs.rsp - a)})")

        for a in history_out:
            print(f"History: 0x{a:x}")

        for a in path_out:
            ptr, offset = a
            print(f"Access: 0x{ptr:x} + 0x{offset:x}")

        chain_pre = "(* _varhax"
        chain_post = ")"
        for a in path_out[::-1]:
            ptr, offset = a
            if offset == 0:
                chain_pre = "(* " + chain_pre
                chain_post += ")"
            else:
                chain_pre = "(* (" + hex(offset // 8) + " + " + chain_pre
                chain_post += "))"
        typename = f"uint64_t {'*' * (len(path_out) + 1)}"
        print(f"uint64_t stack_diff = $rsp - {hex(pwndbg.regs.rsp - found_addr[0])};")
        print(f"{typename} _varhax = ({typename}) {hex(found_addr[0])};")
        print(f"uint64_t varhax = {chain_pre}{chain_post};")










parser = argparse.ArgumentParser()
parser.description = """
    Find class name from a member pointer.
    """
parser.add_argument("address", type=int, nargs="?", default=0, help="The address of the member.")
@pwndbg.commands.ArgparsedCommand(parser)
def findclass(address=None, offset=8):
    """
    Findclass
    """

    address = int(address)

    objects = {}
    g_objects = pwndbg.symbol.address("__g_objects")
    for i in range(1024):
        addr = g_objects + i * 8 * 3
        # print(f"{addr:x}")
        ptr = int(pwndbg.memory.poi(pwndbg.typeinfo.pvoid, addr))
        if ptr == 0:
            continue

        name = pwndbg.memory.string(pwndbg.memory.poi(pwndbg.typeinfo.pvoid, addr + 8))
        size = int(pwndbg.memory.poi(pwndbg.typeinfo.uint64, addr + 16))
        obj = {
            "start": ptr,
            "end": ptr + size,
            "name":name,
            "size":size,
        }
        # print(f"0x{ptr:x} - 0x{ptr + size:x}: {name}")
        objects[ptr] = obj

    for key in objects.keys():
        obj = objects[key]
        # print(f"Is {address:x} between {obj['start']:x} and {obj['end']:x}?")
        if address >= obj["start"] and address < obj["end"]:
            print(f"0x{address:x} is inside the range of {obj['name']}")
            print(f"Start: 0x{obj['start']:x}")
            break


