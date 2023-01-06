1: 
2: undefined8 FUN_00130fe0(long param_1,ushort **param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: undefined4 uVar3;
8: long lVar4;
9: ushort *puVar5;
10: long lVar6;
11: int iVar7;
12: undefined8 *puVar8;
13: uint uVar9;
14: ulong uVar11;
15: int iVar12;
16: ulong uVar13;
17: undefined8 uStack104;
18: undefined8 uStack96;
19: ulong uStack88;
20: int iStack80;
21: long lStack72;
22: int iVar10;
23: 
24: uVar2 = *(undefined4 *)(param_1 + 0x218);
25: lVar4 = *(long *)(param_1 + 0x250);
26: if ((*(int *)(param_1 + 0x170) != 0) && (*(int *)(lVar4 + 0x3c) == 0)) {
27: iVar7 = *(int *)(lVar4 + 0x20);
28: lVar6 = *(long *)(param_1 + 0x248);
29: if (iVar7 < 0) {
30: iVar7 = iVar7 + 7;
31: }
32: piVar1 = (int *)(lVar6 + 0x24);
33: *piVar1 = *piVar1 + (iVar7 >> 3);
34: *(undefined4 *)(lVar4 + 0x20) = 0;
35: iVar7 = (**(code **)(lVar6 + 0x10))();
36: if (iVar7 == 0) {
37: return 0;
38: }
39: if (0 < *(int *)(param_1 + 0x1b0)) {
40: memset((void *)(lVar4 + 0x2c),0,(long)*(int *)(param_1 + 0x1b0) * 4);
41: }
42: uVar3 = *(undefined4 *)(param_1 + 0x170);
43: *(undefined4 *)(lVar4 + 0x28) = 0;
44: *(undefined4 *)(lVar4 + 0x3c) = uVar3;
45: if (*(int *)(param_1 + 0x21c) == 0) {
46: *(undefined4 *)(lVar4 + 0x10) = 0;
47: }
48: }
49: puVar8 = *(undefined8 **)(param_1 + 0x28);
50: iVar7 = *(int *)(param_1 + 0x1e0);
51: uVar13 = *(ulong *)(lVar4 + 0x18);
52: uVar9 = *(uint *)(lVar4 + 0x20);
53: uVar11 = (ulong)uVar9;
54: uStack104 = *puVar8;
55: uStack96 = puVar8[1];
56: if (0 < iVar7) {
57: iVar12 = 0;
58: lStack72 = param_1;
59: do {
60: puVar5 = *param_2;
61: iVar10 = (int)uVar11;
62: if ((int)uVar11 < 1) {
63: iVar7 = FUN_00125d30(&uStack104,uVar13,uVar11,1);
64: if (iVar7 == 0) {
65: return 0;
66: }
67: iVar7 = *(int *)(param_1 + 0x1e0);
68: uVar13 = uStack88;
69: iVar10 = iStack80;
70: }
71: uVar9 = iVar10 - 1;
72: uVar11 = (ulong)uVar9;
73: if ((uVar13 >> (uVar11 & 0x3f) & 1) != 0) {
74: *puVar5 = *puVar5 | (ushort)(1 << ((byte)uVar2 & 0x1f));
75: }
76: iVar12 = iVar12 + 1;
77: param_2 = param_2 + 1;
78: } while (iVar12 < iVar7);
79: puVar8 = *(undefined8 **)(param_1 + 0x28);
80: }
81: *puVar8 = uStack104;
82: puVar8[1] = uStack96;
83: *(ulong *)(lVar4 + 0x18) = uVar13;
84: *(uint *)(lVar4 + 0x20) = uVar9;
85: *(int *)(lVar4 + 0x3c) = *(int *)(lVar4 + 0x3c) + -1;
86: return 1;
87: }
88: 
