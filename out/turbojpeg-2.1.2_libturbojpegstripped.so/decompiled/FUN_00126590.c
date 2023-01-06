1: 
2: void FUN_00126590(code **param_1,int param_2)
3: 
4: {
5: code **ppcVar1;
6: int iVar2;
7: 
8: iVar2 = *(int *)((long)param_1 + 0x24);
9: if ((iVar2 != 0xcf) && (iVar2 != 0xcc)) {
10: ppcVar1 = (code **)*param_1;
11: *(undefined4 *)(ppcVar1 + 5) = 0x14;
12: *(int *)((long)ppcVar1 + 0x2c) = iVar2;
13: (**ppcVar1)();
14: }
15: iVar2 = 1;
16: if (0 < param_2) {
17: iVar2 = param_2;
18: }
19: if ((*(int *)(param_1[0x48] + 0x24) != 0) && (*(int *)((long)param_1 + 0xac) < iVar2)) {
20: iVar2 = *(int *)((long)param_1 + 0xac);
21: }
22: *(int *)((long)param_1 + 0xb4) = iVar2;
23: FUN_001254e0(param_1);
24: return;
25: }
26: 
