1: 
2: uint FUN_00103300(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: uint uVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: int iVar4;
9: uint uVar5;
10: 
11: if (*(int *)((long)param_1 + 0x24) != 0x66) {
12: pcVar2 = *param_1;
13: *(int *)(pcVar2 + 0x2c) = *(int *)((long)param_1 + 0x24);
14: ppcVar3 = (code **)*param_1;
15: *(undefined4 *)(pcVar2 + 0x28) = 0x14;
16: (**ppcVar3)();
17: }
18: uVar1 = *(uint *)(param_1 + 0x26);
19: if (uVar1 < *(uint *)((long)param_1 + 0x34)) {
20: ppcVar3 = (code **)param_1[2];
21: if (ppcVar3 != (code **)0x0) {
22: ppcVar3[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x34);
23: ppcVar3[1] = (code *)(ulong)uVar1;
24: (**ppcVar3)(param_1);
25: }
26: if (*(int *)(param_1[0x36] + 0x18) != 0) {
27: (**(code **)(param_1[0x36] + 8))(param_1);
28: }
29: uVar1 = *(int *)((long)param_1 + 0x13c) * 8;
30: if (param_3 < uVar1) {
31: ppcVar3 = (code **)*param_1;
32: *(undefined4 *)(ppcVar3 + 5) = 0x17;
33: (**ppcVar3)(param_1);
34: }
35: iVar4 = (**(code **)(param_1[0x39] + 8))(param_1,param_2);
36: uVar5 = 0;
37: if (iVar4 != 0) {
38: *(uint *)(param_1 + 0x26) = *(int *)(param_1 + 0x26) + uVar1;
39: uVar5 = uVar1;
40: }
41: return uVar5;
42: }
43: pcVar2 = *param_1;
44: *(undefined4 *)(pcVar2 + 0x28) = 0x7b;
45: (**(code **)(pcVar2 + 8))(param_1,0xffffffff);
46: return 0;
47: }
48: 
