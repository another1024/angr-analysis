import angr
import tracer
from angr.state_plugins.preconstrainer import SimStatePreconstrainer
from angr.state_plugins.posix import SimSystemPosix
from angr.storage.file import SimFileStream

import logging
logging.getLogger('angr.exploration_techniques').setLevel('DEBUG')

path = '/home/kylebot/src/angr-dev/binaries/tests/cgc/cfe_CADET_00003'
inp = b'A'*0x80

proj = angr.Project(path)

input_file = SimFileStream(name='stdin', ident='aeg_stdin')
state = proj.factory.full_init_state(stdin=input_file)
state.preconstrainer.preconstrain_file(inp, input_file, set_length=True)
#通过插件指定预约束，执行指定的输入
simgr = proj.factory.simgr(state)
runner = tracer.QEMURunner(path, inp)
#通过qemu获取执行的tracer块地址
tracer_tech = angr.exploration_techniques.Tracer(trace=runner.trace, crash_addr=runner.crash_addr)
#通过使用angr的tracer插件，不断记录angr在预约束下的路径是否与qemu相同
simgr.use_technique(tracer_tech)

simgr.run()
#获取指定state后通过添加约束找到新的路径或者crash内容
found = simgr.traced[0]

print('preconstraint:', len(found.preconstrainer.preconstraints))
print('before simplification:', len(found.solver.constraints))
found.solver.simplify()
print('after simplification:', len(found.solver.constraints))
found.preconstrainer.remove_preconstraints()
print('after remove preconstraints:', len(found.solver.constraints))
