1: 
2: void FUN_00131870(long param_1)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: long lVar3;
8: uint uVar4;
9: uint uVar5;
10: long in_R8;
11: uint *in_R9;
12: uint uVar6;
13: int in_stack_00000008;
14: 
15: lVar2 = *(long *)(param_1 + 0x238);
16: uVar1 = *(uint *)(lVar2 + 0x28);
17: if (uVar1 == 0) {
18: lVar3 = (**(code **)(*(long *)(param_1 + 8) + 0x38))
19: (param_1,*(undefined8 *)(lVar2 + 0x10),*(undefined4 *)(lVar2 + 0x24),
20: *(undefined4 *)(lVar2 + 0x20),0);
21: uVar1 = *(uint *)(lVar2 + 0x28);
22: *(long *)(lVar2 + 0x18) = lVar3;
23: }
24: else {
25: lVar3 = *(long *)(lVar2 + 0x18);
26: }
27: uVar4 = *(int *)(param_1 + 0x8c) - *(int *)(lVar2 + 0x24);
28: uVar6 = in_stack_00000008 - *in_R9;
29: uVar5 = *(int *)(lVar2 + 0x20) - uVar1;
30: if (uVar6 <= uVar4) {
31: uVar4 = uVar6;
32: }
33: if (uVar4 <= uVar5) {
34: uVar5 = uVar4;
35: }
36: (**(code **)(*(long *)(param_1 + 0x270) + 8))
37: (param_1,lVar3 + (ulong)uVar1 * 8,in_R8 + (ulong)*in_R9 * 8,uVar5);
38: *in_R9 = *in_R9 + uVar5;
39: uVar5 = uVar5 + *(int *)(lVar2 + 0x28);
40: *(uint *)(lVar2 + 0x28) = uVar5;
41: if (*(uint *)(lVar2 + 0x20) <= uVar5) {
42: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + *(uint *)(lVar2 + 0x20);
43: *(undefined4 *)(lVar2 + 0x28) = 0;
44: }
45: return;
46: }
47: 
