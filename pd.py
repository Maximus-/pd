# PD - Best debug; Fork of PEDA
# TODO: syscalls
import inspect
import struct
import sys
import os

__gdbModule = None
__lldbModule = None

def unpack(fmt, data): 
    size = struct.calcsize(fmt)
    rfmt = fmt
    outp = struct.unpack(rfmt, data)
    if len(outp) == 1:
        return outp[0]
    return outp

def is_all_ascii(data):
    for i in range(8):
        ind_byte = (data >> (8 * i)) & 0xff
        if ind_byte < 0x20 or ind_byte > 0x7e:
            return False
    return True

def magic_str_to_int(strnum):
    if len(strnum) > 2:
        if strnum[0:2] == '0x':
            return int(strnum, 16)
        elif strnum[0:2] == '0b':
            return int(strnum, 2)
        # Only accept _explicit_ octal style
        elif strnum[0:2] == '0o':
            return int(strnum, 8)
    # Either it's just a two digit number, or it's decimal
    return int(strnum, 10)

# --- try import dbg lib ---
try:
    import gdb
    __gdbModule = gdb
except ImportError:
    pass

try:
    import lldb
    __lldbModule = lldb
except ImportError:
    pass
# --- end try import dbg lib --- 

def _throw_unimpl():
    raise Exception('Method unimplemented: ' + repr(inspect.stack()))

# --- color helpers ---
_START_ATTR = '\x1b['
_RESET_ATTRS = '\x1b[0m'

def red(x):
    return _START_ATTR + '31m' + x + _RESET_ATTRS

def green(x):
    return _START_ATTR + '32m' + x + _RESET_ATTRS

def blue(x):
    return _START_ATTR + '34m' + x + _RESET_ATTRS

def bold(x):
    return _START_ATTR + '1m' + x + _RESET_ATTRS
# --- end color helpers ---

(OS_MAC, OS_LINUX, OS_UNK) = range(3)
(ARCH_X86, ARCH_X64, ARCH_UNK) = range(3)

class ArchInfo():
    def __init__(self, host_arch, host_os, ptr_size, regs, pc, stack_pointer, flags_reg, flags):
        self.pointer_size = ptr_size
        self.gp_regs = regs
        self.stack_pointer = stack_pointer
        self.gp_flags = flags_reg
        self.flags = flags
        self.arch = host_arch
        self.os = host_os
        self.pc_reg = pc

class MemoryMap():
    def __init__(self, begin, end, is_readable, is_writeable, is_executable, name):
        self.begin = begin
        self.end = end
        self.is_readable = is_readable
        self.is_writeable = is_writeable
        self.is_executable = is_executable
        self.permissions_string = ''
        if self.is_readable:
            self.permissions_string += 'r'
        else:
            self.permissions_string += '-'

        if self.is_writeable:
            self.permissions_string += 'w'
        else:
            self.permissions_string += '-'

        if self.is_executable:
            self.permissions_string += 'x'
        else:
            self.permissions_string += '-'

        self.name = name

    def pretty_print(self):
        _name = self.name
        if _name == '':
            _name = '(anon)'
        region_description = '%016x-%016x %s (%s)' % (self.begin, self.end, _name, self.permissions_string)
        if self.is_executable:
            print(red(region_description))
        elif self.is_writeable:
            print(blue(region_description))
        else:
            print(region_description)

# Debugger
#   - get_pid
#   - set_asm_syntax
#   - set_prompt
#   - clear_screen
#   - get_gp_registers
#   - get_gpr_val
#   - get_memory
#   - get_virtual_maps
#   - get_permissions_for_addr
#   - get_map_region_for_ptr
#   - is_mapped
#   - get_heap_base
#   - get_current_disasm
#   - shell

class Debugger:
    current_arch = None
    def set_prompt(self, astr):
        _throw_unimpl()

    def get_pid(self):
        _throw_unimpl()
    
    def set_syntax(self, syntax):
        _throw_unimpl()

    def clear_screen(self):
        sys.stdout.write("\x1b[2J\x1b[H")

    def get_gp_registers(self):
        _throw_unimpl()

    def get_gpr_val(self, reg):
        _throw_unimpl()

    def get_memory(self, addr):
        _throw_unimpl()

    def get_arch(self):
        _throw_unimpl()

    def get_virtual_maps(self):
        # should i really make this a binary heap?
        # maybe premature optimization
        _throw_unimpl()

    def get_heap_base(self):
        vmaps = self.get_virtual_maps()
        for mp in vmaps:
            if mp.name == "[heap]":
                return mp
        return None

    def get_current_disasm(self):
        return "disasm"

    def parse_linux_vmmap(self, memstr):
        full_maps = []

        maps = memstr.split('\n')
        for lm in maps:
            if len(lm) == 0: 
                continue
            terms = lm.split(' ')
            beg = int(terms[0].split('-')[0], 16)
            end = int(terms[0].split('-')[1], 16)
            # this is gross 
            full_maps.append(MemoryMap(beg, end, terms[1][0] == 'r', terms[1][1] == 'w', terms[1][2] == 'x', terms[-1]))
        
        return full_maps

    def get_permissions_for_addr(self, addr):
        _throw_unimpl()

    def is_mapped(self, addr):
        _throw_unimpl()

    def print_gp_registers(self, regs):
        print(red('[-------registers------]'))

        for r in self.current_arch.gp_regs:
            if r in regs:
                v = regs[r]
                print(green(r.upper().ljust(3, ' ')) + ': ' + '0x{:x}'.format(v))

        flags = self.current_arch.gp_flags
        if flags in regs:
            curr_flags = regs[flags]
            flags_line = red(flags.upper()) + ': ' + '0x{:x}'.format(curr_flags)
            flags_line += ' ('
            fls = []
            for fl in self.current_arch.flags:
                if (1 << fl) & curr_flags:
                    fls.append(bold(red(self.current_arch.flags[fl].upper())))
                else:
                    fls.append(green(self.current_arch.flags[fl].lower()))

            flags_line += ' '.join(fls)
            flags_line += ')'
            print(flags_line)

    def telescope(self, addr, num):
        memmaps = self.get_virtual_maps()
        for i in range(num):
            mem_val = int(unpack("<Q", (self.get_memory(addr + 8*i, 8))))

            # sline is a text run
            sline = '%04d| ' % (8 * i) + blue(hex(addr + 8 * i)) + ' -> ' + hex(mem_val)

            iterval = mem_val
            
            for i in range(10):
                mp = self.get_map_region_for_ptr(iterval, maps=memmaps)

                if not mp is None and mp.is_readable:
                    iterval = int(unpack("<Q", self.get_memory(iterval, 8)))
                    sline += ' -> ' + hex(iterval)
                    # Determine if iterval is ascii.. if so, fetch the rest
                else:
                    break

            print(sline)

    def shell(self, cmd):
        _throw_unimpl()
    
    def print_disasm(self):
        print(red('[---------code---------]'))

        disasm = self.get_current_disasm()
        if not disasm is None:
            print(disasm)
    
    def get_map_region_for_ptr(self, ptr, maps=None):
        if maps is None:
            maps = self.get_virtual_maps()

        if maps is None:
            return None
        
        for mp in maps:
            if ptr > mp.begin and ptr < mp.end:
                return mp

        return None

    def print_stack(self):
        print(red('[---------stack--------]'))
        sp = self.get_gpr_val(self.current_arch.stack_pointer)
    
        if sp is None:
            return

        self.telescope(sp, 8) # Default telescope depth

class GDBDBG(Debugger):
    def register_hooks(self):
        gdb.events.stop.connect(stop_hook)

    def shell(self, cmd):
        # will need a hack to capture this..
        return self._executeCommand('shell ' + cmd)

    def get_current_frame(self):
        return gdb.selected_frame()

    def get_gp_registers(self):
        regs = gdb.execute('info registers', to_string=True)
        rlines = regs.split('\n')
        regs = dict()
        for line in rlines:
            rv = line.split()
            if len(rv) == 0:
                continue
            rname = rv[0]
            rval = rv[1]
            regs[rname] = int(rval, 16)

        if regs['eflags']:
            regs['rflags'] = regs['eflags']

        return regs

    def get_virtual_maps(self):
        #if current_arch.os == OS_LINUX:
        #   _throw_unimpl()
        #elif current_arch.os == OS_MAC:
        #   _throw_unimpl()
        return []

    def get_gpr_val(self, reg):
        return self.get_gp_registers()[reg]

    def get_arch(self):
        return ARCH_X64, 8

    def set_syntax(self, syntax):
        self._executeCommand("set disassembly-flavor " + syntax)

    def stop_hook(a, b):
        print('bbbbb')

    def initialize_ui(self):
        self._executeCommand('set height 0')

    def add_aliases(self):
        pass

    def _executeCommand(self, st):
        return gdb.execute(st)

    # for some reason, calling set height 0 with to_string=True 
    # doesnt do anything...
    def _executeCommandWithResponse(self, st):
        return gdb.execute(st, to_string=True)

    def set_prompt(self, pstr):
        self._executeCommand('set prompt ' + red(pstr))
        pass

    def get_memory(self, addr, size):
        inf = gdb.inferiors()[0]
        mem = inf.read_memory(addr, size) 
        return mem.tobytes()

class LLDBDBG(Debugger):
    debugger = None
    def __init__(self):
        self.debugger = lldb.debugger
        self.debugger.SetAsync(True)
    
    def register_hooks(self):
        self._executeCommand('target stop-hook add -o context')
    
    def get_arch(self):
        triple = lldb.debugger.GetSelectedTarget().GetTriple()
        triple = triple.split('-')
        arch = ARCH_UNK
        ptr_size = 4

        if 'x86_64' in triple:
            arch = ARCH_X64
            ptr_size = 8
        if 'x86' in triple:
            arch = ARCH_X86
            ptr_size = 4
        
        return arch, ptr_size

    def get_memory(self, addr, size):
        err = lldb.SBError()
        process = self.get_current_process()
        mem = process.ReadMemory(addr, size, err)
        return mem

    def initialize_ui(self):
        self._executeCommand('settings set stop-disassembly-display never')

    def set_syntax(self, syntax):
        self._executeCommand('settings set target.x86-disassembly-flavor ' + syntax)
    
    def get_gpr_val(self, reg):
        regs = self.get_gp_registers()
        if reg in regs:
            return regs[reg]
        return None

    def shell(self, cmd):
        return os.system(cmd)

    def get_current_disasm(self):
        cframe = self.get_current_frame()
        if cframe is None:
            return
        vv = cframe.Disassemble()
        if vv is None:
            return
        vv = vv.split('\n')[:-1]
        found_c = -1
        disasm = []
        for l in vv:
            if len(disasm) > 7:
                disasm = disasm[1:]
            disasm.append(l)
            if l[0:2] == '->':
                found_c = 0

            if found_c >= 0:
                found_c += 1

            if found_c == 5:
                break

        return '\n'.join(disasm)

    def get_pid(self):
        return self.get_current_process().id

    def get_current_process(self):
        return lldb.debugger.GetSelectedTarget().GetProcess()

    def get_current_frame(self):
        return self.get_current_process().GetSelectedThread().GetSelectedFrame()

    def get_gp_registers(self):
        frame = self.get_current_frame()
        #print(frame.GetRegisters())
        gprs = None
        for rset in frame.GetRegisters():
            if str(rset.GetName()).startswith('General'):
                gprs = rset
                break
        #gprs = frame.GetRegisters().GetFirstValueByName('General Purpose Registers')

        rvals = dict()

        if not gprs is None and gprs.IsValid():
            for reg in gprs:
                rvals[reg.GetName()] = int(reg.GetValue(), 16)
        return rvals

    def initialize_ui(self):
        self._executeCommand("settings set stop-disassembly-display never")
        pass

    def start(self, cmd, result, m, b, c=None):
        self._executeCommand('process launch --stop-at-entry')
    
    def get_all_memory_sections(self):
        # currently missing stack and heap.. great i know
        # lldb-devs mentions how its not possible, but vmmap does it :(

        process = self.get_current_process()
    
        region_list = process.GetMemoryRegions()

        maps = []
        for i in range(region_list.GetSize()):
            region = lldb.SBMemoryRegionInfo()

            region_list.GetMemoryRegionAtIndex(i, region)

            begin_address = region.GetRegionBase()
            end_address = region.GetRegionEnd() - 1
            name = region.GetName() 
            if name is None:
                name = ''
            perm_str = ''

            maps.append(MemoryMap(begin_address, end_address, region.IsReadable(), region.IsWritable(), region.IsExecutable(), name))

        return maps

        #target = lldb.debugger.GetSelectedTarget()
        #mods_count = target.GetNumModules()

        #for i in range(mods_count):
        #    mod = target.GetModuleAtIndex(i)

        #    mod_sections = mod.GetNumSections()
        #    for j in range(mod_sections):
        #        section = mod.GetSectionAtIndex(j)
        #        base = int(section.GetLoadAddress(target))
        #        if base == lldb.LLDB_INVALID_ADDRESS:
        #            base = int(section.addr)
        #        
        #        end = base + int(section.GetByteSize())

        #        perms = section.GetPermissions()
        #        perm_str = ''

        #        if perms & 0x2:
        #            perm_str = 'r'
        #        else:
        #            perm_str = '-'
        #        if perms & 0x1:
        #            perm_str += 'w'
        #        else:
        #            perm_str += '-'
        #        if perms & 0x4:
        #            perm_str += 'x'
        #        else:
        #            perm_str += '-'

        #        name = section.GetName() + " @ " + str(mod.platform_file)
        #        
        #        maps.append(MemoryMap(base, end, perm_str, name))
        #return maps
    
    def get_virtual_maps(self):
        proc = self.get_current_process()
        pid = proc.GetProcessID()

        if self.current_arch.os == OS_LINUX:
            maps = open('/proc/' + str(pid) + '/maps', 'rb').read()
            return self.parse_linux_vmmap(maps)
        elif self.current_arch.os == OS_MAC:
            return self.get_all_memory_sections()

        return []

    def do_vmmap(self, cmd, args, m, b, c=None):
        vmaps = self.get_virtual_maps()
        if vmaps is None:
            print("Couldn't get virtual memory maps... :(")
            return

        if len(args) == 0:
            # No arguments, print all regions
            # print all regions
            for mp in vmaps:
                mp.pretty_print()
            return

        address = None
        # For the world where someone has something mapped below 99...
        # I think __PAGEZERO and MMAP_MIN_ADDR prevent this
        # But only for non-root? 
        address = magic_str_to_int(args)

        for mp in vmaps:
            if address >= mp.begin and address < mp.end:
                mp.pretty_print()
                break

    def do_telescope(self, cmd, args, m, b, c=None):
        # How does this work without args again?
        # I think it's just the current stack walk?

        numc = 8 
        address = None

        if len(args) > 0:
            # Attempt to split it first
            arglist = args.split(' ')
            if len(arglist) > 1:
                address = magic_str_to_int(arglist[0])
                numc = magic_str_to_int(arglist[1])
            else:
                address = magic_str_to_int(args)
        else:
            address = self.get_gpr_val(dbg.current_arch.stack_pointer)

        self.telescope(address, numc)

    def add_aliases(self):
        self._executeCommand('command script add --function pd.context context')
        self._executeCommand('command script add --function pd.context ctx')
        self._executeCommand('command script add --function pd.context ct')

        self._executeCommand('command script add --function pd.dbg.start start')

        self._executeCommand('command script add --function pd.dbg.do_vmmap vmmap')
        self._executeCommand('command script add --function pd.dbg.do_vmmap vmm')
        self._executeCommand('command script add --function pd.dbg.do_telescope telescope')
        self._executeCommand('command script add --function pd.dbg.do_telescope tele')
        # searchmem, tls, deactive, checksec, aslr, print disassembly, stepuntil
        # xrefs, heap stuff
        # libc, heap, ld (print base)
        # heapinfo, magic, one_gadget, canary
        # findmainarea, fpu (floating point registers/stack)

    def _executeCommand(self, inp):
        self.debugger.HandleCommand(inp)

    def set_prompt(self, pstr):
        self._executeCommand("settings set prompt '" + pstr + "'")

    def _executeCommandWithRet(self, s):
        ret = lldb.SBCommandReturnObject()
        err = self.debugger.GetCommandInterpreter().HandleCommand(s, ret)
        return ret, err

    def _executeCommand(self, st):
        self.debugger.HandleCommand(st)

    def set_prompt(self, pstr):
        self._executeCommand("settings set prompt '" + pstr + "'")
        pass

# --- setup debugger instance --- 
dbg = None

if __gdbModule is not None:
    dbg = GDBDBG()
if __lldbModule is not None:
    dbg = LLDBDBG()

if dbg is None:
    print('What debugger are you using?')
    raise Exception('Cannot determine debugger')
# --- Handle UI --- 

def context(*args):
    if dbg.current_arch is None:
        dbg.current_arch = determine_arch()
    regs = dbg.get_gp_registers()
    dbg.clear_screen()
    dbg.print_gp_registers(regs)
    dbg.print_disasm()
    dbg.print_stack()

def stop_hook(*args):
    context(args)

# --- hopefully figured out debugger --- 
# --- run initialization ---

# maybe this should be a better data type.. that way i can look up 'ah' -> 'eax' easily
# also handling flags..

arch_gpr_map = {
        ARCH_X86:       {   'gpr': ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags'], 
                        'pc': 'eip',
                        'sp': 'esp',
                        'flags_reg': 'eflags',
                        'flags': { 1: 'CF', 2: 'PF', 4: 'AF', 6: 'ZF', 7: 'SF', 8: 'TF', 9: 'IF', 10: 'DF', 11: 'OF' }
                        },
        ARCH_X64:   {   'gpr': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'], 
                        'pc': 'rip',
                        'sp': 'rsp',
                        'flags_reg': 'rflags',
                        'flags': { 1: 'CF', 2: 'PF', 4: 'AF', 6: 'ZF', 7: 'SF', 8: 'TF', 9: 'IF', 10: 'DF', 11: 'OF' }
                        }
}

def determine_arch():
    archs, size = dbg.get_arch()
    arch_gpregs = []
    flags_gpreg = None
    stack_pointer = None
    flags = None

    archs = ARCH_X64

    if archs in arch_gpr_map:
        arch_gpregs = arch_gpr_map[archs]['gpr']
        flags_gpreg = arch_gpr_map[archs]['flags_reg']
        stack_pointer = arch_gpr_map[archs]['sp']
        flags = arch_gpr_map[archs]['flags']
        pc = arch_gpr_map[archs]['pc']
    else:
        print('Unsupported arch?')
        return
    
    hostos = None
    uname = os.uname()[0]
    if uname == "Linux":
        hostos = OS_LINUX
    elif uname == "Darwin":
        hostos = OS_MAC
    if hostos is None:
        hostos = OS_UNK
        print("Unknown arch.. beware")

    hostos = OS_MAC

    return ArchInfo(archs, hostos, size, arch_gpregs, pc, stack_pointer, flags_gpreg, flags)

dbg.set_prompt("(pd) ")

dbg.add_aliases()
dbg.initialize_ui()
dbg.set_syntax('intel') # you want this

dbg.register_hooks()

