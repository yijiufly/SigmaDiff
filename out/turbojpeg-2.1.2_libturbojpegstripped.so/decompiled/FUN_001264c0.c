1: 
2: uint FUN_001264c0(code **param_1,undefined8 param_2,uint param_3)
3: 
4: {
5: code **ppcVar1;
6: code *pcVar2;
7: int iVar3;
8: uint uVar4;
9: 
10: iVar3 = *(int *)((long)param_1 + 0x24);
11: if (iVar3 != 0xce) {
12: ppcVar1 = (code **)*param_1;
13: *(undefined4 *)(ppcVar1 + 5) = 0x14;
14: *(int *)((long)ppcVar1 + 0x2c) = iVar3;
15: (**ppcVar1)();
16: }
17: uVar4 = *(uint *)(param_1 + 0x15);
18: if (uVar4 < *(uint *)((long)param_1 + 0x8c)) {
19: ppcVar1 = (code **)param_1[2];
20: if (ppcVar1 != (code **)0x0) {
21: ppcVar1[2] = (code *)(ulong)*(uint *)((long)param_1 + 0x8c);
22: ppcVar1[1] = (code *)(ulong)uVar4;
23: (**ppcVar1)(param_1);
24: }
25: uVar4 = *(int *)((long)param_1 + 0x19c) * *(int *)(param_1 + 0x34);
26: if (param_3 < uVar4) {
27: ppcVar1 = (code **)*param_1;
28: *(undefined4 *)(ppcVar1 + 5) = 0x17;
29: (**ppcVar1)(param_1);
30: }
31: iVar3 = (**(code **)(param_1[0x46] + 0x18))(param_1,param_2);
32: if (iVar3 == 0) {
33: uVar4 = 0;
34: }
35: else {
36: *(uint *)(param_1 + 0x15) = *(int *)(param_1 + 0x15) + uVar4;
37: }
38: }
39: else {
40: pcVar2 = *param_1;
41: uVar4 = 0;
42: *(undefined4 *)(pcVar2 + 0x28) = 0x7b;
43: (**(code **)(pcVar2 + 8))(param_1,0xffffffff);
44: }
45: return uVar4;
46: }
47: 
