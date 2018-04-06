# PD - Best debug; Fork of PEDA
# TODO: syscalls
import inspect

__gdbModule = None
__lldbModule = None

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
    raise Exception('Method unimplemented: ' + inspect.stack()[0][3])

_START_COLOR = '\x1b['
_RESET_ATTRS = '\x1b[0m'

def red(x):
    return _START_COLOR + '31m' + x + _RESET_ATTRS

current_arch = None
pointer_size = 0
arch_gpregs = []

class Debugger:
    def set_prompt(self, astr):
        _throw_unimpl()
    
    def set_syntax(self, syntax):
        _throw_unimpl()

    def get_gpr_registers(self):
        _throw_unimpl()

    def get_arch(self):
        _throw_unimpl()

    def print_gp_registers(self, regs):
        print(red('Registers...'))

        for r in arch_gpregs:
            v = regs[r]
            print(r.upper().ljust(3, ' ') + ': ' + v)

        print('End Registers...')

    def prettyPrintCode(self, code):
        print('Code...')
        print(code)
        print('End Code...')

    def prettyPrintStack(self, stack):
        print('Stack...')
        print(stack)
        print('End Stack...')

class GDBDBG(Debugger):
    def register_hooks(self):
        gdb.events.stop.connect(stop_hook)

    def stop_hook(a, b):
        print('bbbbb')

    def initialize_ui(self):
        pass

    def add_aliases(self):
        pass

    def _executeCommand(self, str):
        pass

    def set_prompt(self, pstr):
        gdb.execute('set prompt ' + red(pstr))
        pass

class LLDBDBG(Debugger):
    debugger = None
    def __init__(self):
        self.debugger = lldb.debugger
    
    def register_hooks(self):
        self._executeCommand('target stop-hook add -o context')
    
    def get_arch(self):
        return "x86_64", 8

    def initialize_ui(self):
        self._executeCommand('settings set stop-disassembly-display never')

    def set_syntax(self, syntax):
        self._executeCommand('settings set target.x86-disassembly-flavor ' + syntax)
    
    def _hard_get_registers(self, debugger):
        #ret, err = self._executeCommandWithRet(debugger, 'register read')
        #print(ret.GetOutput())
        # this is for when the frame just doesn't have registers for some reason...
        pass

    def get_current_frame(self):
        return lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()

    def get_gpr_registers(self):
        frame = self.get_current_frame()
        #print(frame.GetRegisters())
        gprs = frame.GetRegisters().GetFirstValueByName('General Purpose Registers')

        rvals = dict()

        if not gprs.IsValid():
            print('Empty register set.. should hard get?')
            #regs = self._hard_get_registers(debugger)
        else:
            for reg in gprs:
                rvals[reg.GetName()] = reg.GetValue()
        return rvals
        
    def print_disasm(self):
        print(red('mov rax, rax'))
    
    def print_stack(self):
        print(red('00000000000'))

    def initialize_ui(self):
        pass
    
    def start(self, cmd, result, m, b, c):
        self._executeCommand('process launch --stop-at-entry')
    
    def vmmap(self, cmd, result, m, b, c):
        pass

    def add_aliases(self):
        self._executeCommand('command script add --function pd.context context')
        self._executeCommand('command script add --function pd.context ctx')
        self._executeCommand('command script add --function pd.context ct')

        self._executeCommand('command script add --function pd.dbg.start start')

        self._executeCommand('command script add --function pd.dbg.vmmap vmmap')
        self._executeCommand('command script add --function pd.dbg.vmmap vmm')
        # tele, searchmem, tls, deactive, checksec, aslr, print disassembly, stepuntil
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

    def _executeCommand(self, str):
        self.debugger.HandleCommand(str)

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
    if current_arch is None:
        determine_arch()
    regs = dbg.get_gpr_registers()
    dbg.print_gp_registers(regs)
    dbg.print_disasm()
    dbg.print_stack()

def stop_hook(*args):
    lldb.SBPlatformShellCommand().Clear()
    context(args)

# --- hopefully figured out debugger --- 
# --- run initialization ---

# maybe this should be a better data type.. that way i can look up 'ah' -> 'eax' easily
arch_gpr_map = {
    'x86':      ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags'],
    'x86_64':   ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rflags']
}

def determine_arch():
    global current_arch
    global pointer_size
    global arch_gpregs
    archs, size = dbg.get_arch()

    if archs in arch_gpr_map:
        arch_gpregs = arch_gpr_map[archs]
    else:
        print('Unsupported arch?')

    pointer_size = size
    current_arch = archs
    print(arch_gpregs)
    print(current_arch)

dbg.set_prompt("(pd) ")

dbg.add_aliases()
dbg.initialize_ui()
dbg.set_syntax('intel') # you want this

dbg.register_hooks()
