| 操作                                                         | 对应                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| class ReplacementCheckEquals(angr.SimProcedure)              | 对应SimProcedure.py里面的 SimProcedure类                     |
| project.factory.entry_state()                                | 对应 factory.py里面的 entry_state状态转换                    |
| simulation = project.factory.simgr(initial_state)            | 对应 factory.py里面的函数返回simmanage.py里面的simmanage类   |
| simulation.explore(find=is_successful, avoid=should_abort) （.step）（.run） | 对应simmanage.py里面的explore（step）（run）                 |
| proj.analyses.CFGFast()                                      | 对应 analysis里面的forward_analysis.py文件的_analysis函数    |
| driller                                                      | 对应afl调用driller，driller_callback（在local_callback.py里面） |
| project = angr.Project(path_to_binary)                       | 对应project.py文件里的project类的init                        |

