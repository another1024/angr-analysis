from ....errors import UnsupportedIRStmtError, UnsupportedDirtyError, SimStatementError
from .... import sim_options as o

from .base import SimIRStmt
from .noop import SimIRStmt_NoOp
from .imark import SimIRStmt_IMark
from .abihint import SimIRStmt_AbiHint
from .wrtmp import SimIRStmt_WrTmp
from .put import SimIRStmt_Put
from .store import SimIRStmt_Store
from .mbe import SimIRStmt_MBE
from .dirty import SimIRStmt_Dirty
from .exit import SimIRStmt_Exit
from .cas import SimIRStmt_CAS
from .storeg import SimIRStmt_StoreG
from .loadg import SimIRStmt_LoadG
from .llsc import SimIRStmt_LLSC
from .puti import SimIRStmt_PutI

import logging
l = logging.getLogger("angr.engines.vex.statements.")

def translate_stmt(stmt, state):
    stmt_name = 'SimIRStmt_' +  type(stmt).__name__.split('IRStmt')[-1].split('.')[-1]

    if stmt_name in globals():
        stmt_class = globals()[stmt_name]
        s = stmt_class(stmt, state)
        s.process()
        '''
        调用base父类，父类调用具体子类，相当一个虚拟机，有put，tmp，计数，判断exit等操作对应每个文件的_execute函数
        具体的符号化也在这个里面的
        像这个self.state.registers.store(self.stmt.offset, data.expr, action=a)
        store（storage/文件夹下的memory）
        最终到了state_plugins里面的memory，然后调用求解器
        '''
        return s
    else:
        l.error("Unsupported statement type %s", (type(stmt)))
        if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
            raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
        state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
