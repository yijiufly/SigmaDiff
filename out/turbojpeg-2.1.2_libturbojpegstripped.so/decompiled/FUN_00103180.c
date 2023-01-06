1: 
2: uint FUN_00103180(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: int iVar3;
8: uint uVar4;
9: 
10: iVar3 = *(int *)((long)param_1 + 0x24);
11: if (iVar3 != 0x66) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x14;
14: *(int *)((long)ppcVar1 + 0x2c) = iVar3;
15: (**ppcVar1)();
16: }
17: uVar4 = *(uint *)(param_1 + 0x26);
18: if (uVar4 < *(uint *)((long)param_1 + 0x34)) {
19: ppcVar1 = (code **)param_1[2];
20: if (ppcVar1 != (code **)0x0) {
21: ppcVar1[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x34);
22: ppcVar1[1] = (code *)(ulong)uVar4;
23: (**ppcVar1)(param_1);
24: }
25: if (*(int *)(param_1[0x36] + 0x18) != 0) {
26: (**(code **)(param_1[0x36] + 8))(param_1);
27: }
28: uVar4 = *(int *)((long)param_1 + 0x13c) * 8;
29: if (param_3 < uVar4) {
30: ppcVar1 = (code **)*param_1;
31: *(undefined4 *)(ppcVar1 + 5) = 0x17;
32: (**ppcVar1)(param_1);
33: }
34: iVar3 = (**(code **)(param_1[0x39] + 8))(param_1,param_2);
35: if (iVar3 == 0) {
36: uVar4 = 0;
37: }
38: else {
39: *(uint *)(param_1 + 0x26) = *(int *)(param_1 + 0x26) + uVar4;
40: }
41: }
42: else {
43: pcVar2 = *param_1;
44: uVar4 = 0;
45: *(undefined4 *)(pcVar2 + 0x28) = 0x7b;
46: (**(code **)(pcVar2 + 8))(param_1,0xffffffff);
47: }
48: return uVar4;
49: }
50: 
