1: 
2: void FUN_0013c730(long param_1)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: uint uVar3;
8: long lVar4;
9: int iVar5;
10: int iVar6;
11: long in_R8;
12: uint *in_R9;
13: uint uVar7;
14: int in_stack_00000008;
15: 
16: lVar2 = *(long *)(param_1 + 0x238);
17: uVar1 = *(uint *)(lVar2 + 0x28);
18: iVar5 = *(int *)(lVar2 + 0x20);
19: iVar6 = *(int *)(lVar2 + 0x24);
20: if (uVar1 == 0) {
21: lVar4 = (**(code **)(*(long *)(param_1 + 8) + 0x38))();
22: uVar1 = *(uint *)(lVar2 + 0x28);
23: iVar5 = *(int *)(lVar2 + 0x20);
24: iVar6 = *(int *)(lVar2 + 0x24);
25: *(long *)(lVar2 + 0x18) = lVar4;
26: }
27: else {
28: lVar4 = *(long *)(lVar2 + 0x18);
29: }
30: uVar7 = *(int *)(param_1 + 0x8c) - iVar6;
31: uVar3 = iVar5 - uVar1;
32: if (uVar7 <= iVar5 - uVar1) {
33: uVar3 = uVar7;
34: }
35: uVar7 = in_stack_00000008 - *in_R9;
36: if (uVar3 < uVar7) {
37: uVar7 = uVar3;
38: }
39: (**(code **)(*(long *)(param_1 + 0x270) + 8))
40: (param_1,lVar4 + (ulong)uVar1 * 8,in_R8 + (ulong)*in_R9 * 8,uVar7);
41: *in_R9 = *in_R9 + uVar7;
42: uVar7 = uVar7 + *(int *)(lVar2 + 0x28);
43: *(uint *)(lVar2 + 0x28) = uVar7;
44: if (*(uint *)(lVar2 + 0x20) <= uVar7) {
45: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + *(uint *)(lVar2 + 0x20);
46: *(undefined4 *)(lVar2 + 0x28) = 0;
47: }
48: return;
49: }
50: 
