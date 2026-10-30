"""契约层测试包标记。

为什么要有这个空文件：``apps/api/tests`` 与 ``packages/contracts/tests`` 各有一个
``conftest.py``。两个目录都不是包时，pytest 的默认 ``prepend`` 导入模式会把两者
都以顶层模块名 ``conftest`` 注册，先导入的那个获胜——于是 ``pytest apps packages``
一把梭时，``apps/api/tests`` 里的 ``from conftest import make_subject`` 会解析到
契约层的 conftest 并 ``ImportError``。

把契约层测试声明为包后，它的 conftest 以 ``packages.contracts.tests.conftest``
注册，与 ``apps/api/tests`` 的顶层 ``conftest`` 不再同名。CI 本来就是分开跑两个
目录的，这个标记只是让本地「一次跑全部」也能得到与 CI 相同的结果。
"""
