1: 
2: undefined8 FUN_00141540(long *param_1,long param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: undefined2 *puVar3;
8: int iVar4;
9: uint uVar5;
10: int iVar6;
11: long lVar7;
12: ulong uVar8;
13: long lVar9;
14: uint uVar10;
15: long lVar11;
16: long lVar12;
17: 
18: lVar2 = param_1[0x4a];
19: if (*(int *)(param_1 + 0x2e) != 0) {
20: iVar4 = *(int *)(lVar2 + 0x4c);
21: if (iVar4 == 0) {
22: FUN_00140730(param_1);
23: iVar4 = *(int *)(lVar2 + 0x4c);
24: }
25: *(int *)(lVar2 + 0x4c) = iVar4 + -1;
26: }
27: if ((*(int *)(lVar2 + 0x28) != -1) && (0 < *(int *)(param_1 + 0x3c))) {
28: lVar9 = 0;
29: do {
30: puVar3 = *(undefined2 **)(param_2 + lVar9 * 8);
31: lVar7 = (long)*(int *)((long)param_1 + lVar9 * 4 + 0x1e4);
32: lVar1 = lVar2 + lVar7 * 4;
33: lVar12 = (long)*(int *)(param_1[lVar7 + 0x37] + 0x14);
34: lVar7 = lVar2 + lVar12 * 8;
35: lVar11 = (long)*(int *)(lVar1 + 0x3c) + *(long *)(lVar7 + 0x50);
36: iVar4 = FUN_00140970(param_1,lVar11);
37: if (iVar4 == 0) {
38: uVar8 = SEXT48(*(int *)(lVar1 + 0x2c));
39: *(undefined4 *)(lVar1 + 0x3c) = 0;
40: }
41: else {
42: iVar4 = FUN_00140970(param_1,lVar11 + 1);
43: lVar11 = lVar11 + 2 + (long)iVar4;
44: uVar5 = FUN_00140970(param_1,lVar11);
45: if (uVar5 != 0) {
46: lVar11 = *(long *)(lVar7 + 0x50) + 0x14;
47: while (iVar6 = FUN_00140970(param_1,lVar11), iVar6 != 0) {
48: uVar5 = uVar5 * 2;
49: if (uVar5 == 0x8000) {
50: lVar9 = *param_1;
51: *(undefined4 *)(lVar9 + 0x28) = 0x7e;
52: (**(code **)(lVar9 + 8))(param_1,0xffffffff);
53: *(undefined4 *)(lVar2 + 0x28) = 0xffffffff;
54: return 1;
55: }
56: lVar11 = lVar11 + 1;
57: }
58: }
59: if ((int)uVar5 < (int)((1 << (*(byte *)((long)param_1 + lVar12 + 0x140) & 0x3f)) >> 1)) {
60: *(undefined4 *)(lVar1 + 0x3c) = 0;
61: }
62: else {
63: if ((int)((1 << (*(byte *)((long)param_1 + lVar12 + 0x150) & 0x3f)) >> 1) < (int)uVar5) {
64: *(int *)(lVar1 + 0x3c) = iVar4 * 4 + 0xc;
65: }
66: else {
67: *(int *)(lVar1 + 0x3c) = iVar4 * 4 + 4;
68: }
69: }
70: uVar10 = uVar5;
71: while (uVar5 = (int)uVar5 >> 1, uVar5 != 0) {
72: iVar6 = FUN_00140970(param_1,lVar11 + 0xe);
73: if (iVar6 != 0) {
74: uVar10 = uVar10 | uVar5;
75: }
76: }
77: iVar6 = uVar10 + 1;
78: if (iVar4 != 0) {
79: iVar6 = -(uVar10 + 1);
80: }
81: uVar5 = iVar6 + *(int *)(lVar1 + 0x2c) & 0xffff;
82: uVar8 = (ulong)uVar5;
83: *(uint *)(lVar1 + 0x2c) = uVar5;
84: }
85: *puVar3 = (short)(uVar8 << ((byte)*(undefined4 *)(param_1 + 0x43) & 0x3f));
86: iVar4 = (int)lVar9 + 1;
87: lVar9 = lVar9 + 1;
88: } while (*(int *)(param_1 + 0x3c) != iVar4 && iVar4 <= *(int *)(param_1 + 0x3c));
89: }
90: return 1;
91: }
92: 
