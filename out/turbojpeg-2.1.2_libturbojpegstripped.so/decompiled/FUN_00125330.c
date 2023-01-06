1: 
2: ulong FUN_00125330(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: ulong uVar3;
8: 
9: iVar1 = *(int *)((long)param_1 + 0x24);
10: if (1 < iVar1 - 200U) {
11: ppcVar2 = (code **)*param_1;
12: *(undefined4 *)(ppcVar2 + 5) = 0x14;
13: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
14: (**ppcVar2)();
15: }
16: uVar3 = FUN_00125060(param_1);
17: if ((int)uVar3 != 2) {
18: return uVar3;
19: }
20: if (param_2 != 0) {
21: ppcVar2 = (code **)*param_1;
22: *(undefined4 *)(ppcVar2 + 5) = 0x33;
23: (**ppcVar2)(param_1);
24: uVar3 = uVar3 & 0xffffffff;
25: }
26: FUN_0011f490(param_1);
27: return uVar3 & 0xffffffff;
28: }
29: 
