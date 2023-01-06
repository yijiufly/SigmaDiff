1: 
2: uint FUN_0011e420(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: code *pcVar1;
6: code **ppcVar2;
7: int iVar3;
8: uint uVar4;
9: uint uVar5;
10: 
11: if (*(int *)((long)param_1 + 0x24) != 0xce) {
12: pcVar1 = *param_1;
13: *(int *)(pcVar1 + 0x2c) = *(int *)((long)param_1 + 0x24);
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(pcVar1 + 0x28) = 0x14;
16: (**ppcVar2)();
17: }
18: uVar5 = *(uint *)(param_1 + 0x15);
19: if (uVar5 < *(uint *)((long)param_1 + 0x8c)) {
20: ppcVar2 = (code **)param_1[2];
21: if (ppcVar2 != (code **)0x0) {
22: ppcVar2[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x8c);
23: ppcVar2[1] = (code *)(ulong)uVar5;
24: (**ppcVar2)(param_1);
25: }
26: uVar5 = *(int *)((long)param_1 + 0x19c) * *(int *)(param_1 + 0x34);
27: if (param_3 < uVar5) {
28: ppcVar2 = (code **)*param_1;
29: *(undefined4 *)(ppcVar2 + 5) = 0x17;
30: (**ppcVar2)(param_1);
31: }
32: iVar3 = (**(code **)(param_1[0x46] + 0x18))(param_1,param_2);
33: uVar4 = 0;
34: if (iVar3 != 0) {
35: *(uint *)(param_1 + 0x15) = *(int *)(param_1 + 0x15) + uVar5;
36: uVar4 = uVar5;
37: }
38: return uVar4;
39: }
40: pcVar1 = *param_1;
41: *(undefined4 *)(pcVar1 + 0x28) = 0x7b;
42: (**(code **)(pcVar1 + 8))(param_1,0xffffffff);
43: return 0;
44: }
45: 
