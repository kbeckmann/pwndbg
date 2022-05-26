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
parser.add_argument("address", type=int, nargs="?", default=0, help="The address of the member.")
parser.add_argument("skip", type=str, nargs="?", default=None, help="Skip pages start addr (0x123,0x456")
@pwndbg.commands.ArgparsedCommand(parser)
def findptr(address=None, skip=None):
    """
    Findptr
    """

    address = int(address)
    skip_pages = []

    if skip is not None:
        for start in skip.split(","):
            skip_pages.append(int(start, 0))

    pages = pwndbg.vmmap.get()

    # calculate total size of mapped memory
    mappings = []
    mapped_mem_size = 0
    for page in pages:
        if not ('[heap' in page.objfile or '[anon' in page.objfile):
            continue
        if int(page.vaddr) in skip_pages:
            # print(f"Skipping 0x{page.vaddr:x}")
            continue
        mappings.append(page)
        mapped_mem_size += page.memsz
    print(f"{mapped_mem_size=}")

    # Find the stack page
    for page in pages:
        if page.is_stack:
            stack = page
            break

    # rsp = 
    stack_start = stack.vaddr
    stack_size = stack.memsz

    # Read the whole stack into maps
    stack_data = pwndbg.memory.read(stack_start, stack_size)
    stack_uint64 = list(struct.unpack(f"<{stack_size // 8}Q", stack_data))
    stack_addr_to_data = {}
    stack_data_to_addr = {}
    for i, val in enumerate(stack_uint64):
        addr = stack.vaddr + i * 8
        stack_addr_to_data[addr] = val
        if val in stack_data_to_addr:
            stack_data_to_addr[val].append(addr)
        else:
            stack_data_to_addr[val] = [addr]

    # for i, key in enumerate(stack_data_to_addr):
    #     print(f"{key:08x}: {len(stack_data_to_addr[key])}")

    # Skip for now!
    # Read all mapped memory (except the stack) into maps
    # mem_addr_to_data = {}
    # mem_data_to_addr = {}
    # for page in pages:
    #     if page.is_stack:
    #         continue
    #     if not ('[heap' in page.objfile or '[anon' in page.objfile):
    #         continue
    
    #     # print(page)

    #     mem_data = pwndbg.memory.read(page.vaddr, page.memsz)
    #     mem_uint64 = list(struct.unpack(f"<{page.memsz // 8}Q", mem_data))
    #     for i, val in enumerate(mem_uint64):
    #         addr = page.vaddr + i * 8
    #         mem_addr_to_data[addr] = val
    #         if val in mem_data_to_addr:
    #             mem_data_to_addr[val].append(addr)
    #         else:
    #             mem_data_to_addr[val] = [addr]

    # print(len(mem_addr_to_data))
    # print(len(mem_data_to_addr))

    # for i, key in enumerate(mem_data_to_addr):
    #     print(f"{key:08x}: {len(mem_data_to_addr[key])}")


    ##########
    ########## ok let's not do this
    # Read all mapped memory map
    # mem_pages = {}
    # for page in pages:
    #     if not ('[heap' in page.objfile or '[anon' in page.objfile):
    #         continue
    #     mem_data = pwndbg.memory.read(page.vaddr, page.memsz)
    #     mem_uint64 = struct.unpack(f"<{page.memsz // 8}Q", mem_data)
    #     mem_pages[page.vaddr] = mem_uint64

    # print(len(mem_addr_to_data))
    # for k, v in enumerate(mem_addr_to_data):
    #     print(f"  {v:016x}: {len(mem_addr_to_data[v])}")

    ##########

    def find_in_ram(value):
        addresses = list(pwndbg.search.search(struct.pack("<Q", value),
                                         mappings=mappings,
                                         executable=False,
                                         writable=False))
        # for a in addresses:
        #     print("FOUND *", hex(a), " == ", hex(value))
        return addresses


        # addresses = []
        # for page_addr in mem_pages:
        #     page = mem_pages[page_addr]
        #     # Do a linear search so we can find all occurrences
        #     for i, x in enumerate(page):
        #         if value == x:
        #             addresses.append(page_addr + i * 8)
        # return addresses

    def find_in_stack(value):
        if value in stack_data_to_addr:
            return stack_data_to_addr[value]
        else:
            return None


    def recurse(addr, history, depth, dig=True):
        if depth > 128:
            return None
        if not is_mapped(addr, pages):
            return None
        if addr in history:
            # print("Skipped (history)", hex(addr))
            return None

        depth += 1
        history.append(addr)

        stack_ptrs = find_in_stack(addr)
        if stack_ptrs is not None:
            print("WIN condition:")
            for a in stack_ptrs:
                print(f"  0x{a:016x}")
            return (stack_ptrs, history)

        # t0 = time.time()
        addresses = find_in_ram(addr)
        # print(time.time() - t0)

        if len(addresses) > 0:
            for a in addresses:
                print(f"  found 0x{a:016x} => 0x{addr:016x}")
                ret = recurse(a, history.copy(), depth)
                if ret is not None:
                    return ret
        elif dig:
            for x in range(64):
                # print("Digging", hex(addr - 8*x))
                ret = recurse(addr - 8*x, history.copy(), depth, False)
                if ret is not None:
                    return ret

        return None


    history = []
    found_addr, history_out = recurse(address, history, 0)
    # print(found_addr)
    for a in found_addr:
        print(f"Found address: 0x{a:016X}")

    for a in history_out:
        print(f"History: 0x{a:016X}")








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
        # print(f"{addr:016x}")
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
        # print(f"0x{ptr:016x} - 0x{ptr + size:016x}: {name}")
        objects[ptr] = obj

    for key in objects.keys():
        obj = objects[key]
        # print(f"Is {address:016x} between {obj['start']:016x} and {obj['end']:016x}?")
        if address >= obj["start"] and address < obj["end"]:
            print(f"0x{address:016x} is inside the range of {obj['name']}")
            print(f"Start: 0x{obj['start']:016x}")
            break


