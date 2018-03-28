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

class Debugger:
    def set_prompt(self, astr):
        _throw_unimpl()

    def prettyPrintRegisters(self, regs):
        print('Registers...')
        print(regs)
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
        gdb.events.stop.connect(self.stop_hook)

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

    def initialize_ui(self):
        self._executeCommand('settings set stop-disassembly-display never')
    
    def context(self, dbger, cmd, ctx, ret, sdict):
        print(red('printing context...'))
        self.printRegisters(dbger)
        self.printCode(dbger)
        self.printStack(dbger)

    def printRegisters(self, debugger):
        self.prettyPrintRegisters(['rax'])
    
    def printCode(self, debugger):
        self.prettyPrintCode('mov rax, rax')
    
    def printStack(self, debugger):
        self.prettyPrintStack('00000000000')

    def initialize_ui(self):
        pass
    
    def start(self, cmd, result, m, b, c):
        self._executeCommand('process launch --stop-at-entry')
    
    def vmmap(self, cmd, result, m, b, c):
        pass

    def add_aliases(self):
        self._executeCommand('command script add --function pd.dbg.context context')
        self._executeCommand('command script add --function pd.dbg.context ctx')
        self._executeCommand('command script add --function pd.dbg.context ct')

        self._executeCommand('command script add --function pd.dbg.start start')

        self._executeCommand('command script add --function pd.dbg.vmmap vmmap')
        self._executeCommand('command script add --function pd.dbg.vmmap vmm')
        # tele, searchmem, tls, deactive, checksec, aslr, print disassembly, stepuntil
        # xrefs, heap stuff
        # libc, heap, ld (print base)
        # heapinfo, magic, one_gadget, canary
        # findmainarea

    def _executeCommandWithRet(self, inp):
        ret = lldb.SBCommandRetwddurnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(inp, ret)
        return ret

    def _executeCommand(self, inp):
        self.debugger.HandleCommand(inp)

    def set_prompt(self, pstr):
        self._executeCommand("settings set prompt '" + pstr + "'")

    def _executeCommandWithRet(self, str):
        ret = lldb.SBCommandRetwddurnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(str, ret)
        return ret

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

# --- hopefully figured out debugger --- 
# --- run initialization ---

dbg.set_prompt("(pd) ")

dbg.add_aliases()
dbg.initialize_ui()

dbg.register_hooks()
