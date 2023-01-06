1: 
2: undefined8 FUN_0011d5b0(long param_1)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: undefined8 uVar3;
8: uint uVar4;
9: uint uVar5;
10: 
11: if (*(int *)(param_1 + 0x24) != 0xcc) {
12: (***(code ***)(param_1 + 0x220))();
13: *(undefined4 *)(param_1 + 0xa8) = 0;
14: *(undefined4 *)(param_1 + 0x24) = 0xcc;
15: }
16: if (*(int *)(*(long *)(param_1 + 0x220) + 0x10) == 0) {
17: LAB_0011d687:
18: *(uint *)(param_1 + 0x24) = 0xce - (uint)(*(int *)(param_1 + 0x5c) == 0);
19: uVar3 = 1;
20: }
21: else {
22: uVar5 = *(uint *)(param_1 + 0xa8);
23: do {
24: while (uVar1 = *(uint *)(param_1 + 0x8c), uVar1 <= uVar5) {
25: (**(code **)(*(long *)(param_1 + 0x220) + 8))(param_1);
26: (***(code ***)(param_1 + 0x220))(param_1);
27: *(undefined4 *)(param_1 + 0xa8) = 0;
28: if (*(int *)(*(long *)(param_1 + 0x220) + 0x10) == 0) goto LAB_0011d687;
29: uVar5 = 0;
30: }
31: ppcVar2 = *(code ***)(param_1 + 0x10);
32: uVar4 = uVar5;
33: if (ppcVar2 != (code **)0x0) {
34: ppcVar2[1] = (code *)(ulong)uVar5;
35: ppcVar2[2] = (code *)(ulong)uVar1;
36: (**ppcVar2)(param_1);
37: uVar4 = *(uint *)(param_1 + 0xa8);
38: }
39: (**(code **)(*(long *)(param_1 + 0x228) + 8))(param_1,0,param_1 + 0xa8);
40: uVar5 = *(uint *)(param_1 + 0xa8);
41: } while (uVar5 != uVar4);
42: uVar3 = 0;
43: }
44: return uVar3;
45: }
46: 
