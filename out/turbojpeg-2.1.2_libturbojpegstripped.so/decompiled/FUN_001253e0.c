1: 
2: undefined4 FUN_001253e0(code **param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: 
8: iVar1 = *(int *)((long)param_1 + 0x24);
9: if (8 < iVar1 - 0xcaU) {
10: ppcVar2 = (code **)*param_1;
11: *(undefined4 *)(ppcVar2 + 5) = 0x14;
12: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
13: (**ppcVar2)();
14: }
15: return *(undefined4 *)(param_1[0x48] + 0x20);
16: }
17: 
