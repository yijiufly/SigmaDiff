1: 
2: ulong FUN_0011d3f0(code **param_1,int param_2)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: ulong uVar3;
8: 
9: if (1 < *(int *)((long)param_1 + 0x24) - 200U) {
10: pcVar1 = *param_1;
11: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
12: ppcVar2 = (code **)*param_1;
13: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
14: (**ppcVar2)();
15: }
16: uVar3 = FUN_0011d100(param_1);
17: if ((int)uVar3 != 2) {
18: return uVar3;
19: }
20: if (param_2 != 0) {
21: ppcVar2 = (code **)*param_1;
22: *(undefined4 *)(ppcVar2 + 5) = 0x33;
23: (**ppcVar2)(param_1);
24: uVar3 = uVar3 & 0xffffffff;
25: }
26: FUN_001166f0(param_1);
27: return uVar3 & 0xffffffff;
28: }
29: 
