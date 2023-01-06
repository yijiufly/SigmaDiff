1: 
2: void FUN_001300d0(long param_1)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: int iVar4;
9: code **ppcVar5;
10: undefined8 uVar6;
11: long lVar7;
12: code *pcVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: 
19: ppcVar5 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x58);
20: *(code ***)(param_1 + 0x260) = ppcVar5;
21: *(undefined4 *)(ppcVar5 + 2) = 0;
22: *ppcVar5 = FUN_0012d3b0;
23: iVar4 = *(int *)(param_1 + 0x19c);
24: *(int *)((long)ppcVar5 + 0x4c) = *(int *)(param_1 + 0x90) * *(int *)(param_1 + 0x88);
25: if (iVar4 == 2) {
26: ppcVar5[1] = FUN_0012ffd0;
27: iVar4 = FUN_001682c0();
28: pcVar8 = FUN_0012e060;
29: if (iVar4 != 0) {
30: pcVar8 = FUN_00168380;
31: }
32: iVar4 = *(int *)(param_1 + 0x40);
33: ppcVar5[3] = pcVar8;
34: if (iVar4 == 0x10) {
35: pcVar8 = FUN_0012fb70;
36: if (*(int *)(param_1 + 0x70) == 0) {
37: pcVar8 = FUN_0012f830;
38: }
39: ppcVar5[3] = pcVar8;
40: }
41: pcVar8 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))
42: (param_1,1,*(undefined4 *)((long)ppcVar5 + 0x4c));
43: ppcVar5[8] = pcVar8;
44: }
45: else {
46: ppcVar5[1] = FUN_0012d3d0;
47: iVar4 = FUN_00168320();
48: if (iVar4 == 0) {
49: iVar4 = *(int *)(param_1 + 0x40);
50: ppcVar5[3] = FUN_0012d400;
51: }
52: else {
53: iVar4 = *(int *)(param_1 + 0x40);
54: ppcVar5[3] = FUN_00168450;
55: }
56: if (iVar4 == 0x10) {
57: pcVar8 = FUN_0012f570;
58: if (*(int *)(param_1 + 0x70) == 0) {
59: pcVar8 = FUN_0012f350;
60: }
61: ppcVar5[3] = pcVar8;
62: }
63: ppcVar5[8] = (code *)0x0;
64: }
65: lVar9 = *(long *)(param_1 + 0x260);
66: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
67: *(undefined8 *)(lVar9 + 0x20) = uVar6;
68: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
69: *(undefined8 *)(lVar9 + 0x28) = uVar6;
70: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
71: *(undefined8 *)(lVar9 + 0x30) = uVar6;
72: lVar7 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
73: lVar1 = *(long *)(lVar9 + 0x20);
74: lVar2 = *(long *)(lVar9 + 0x28);
75: lVar13 = 0x2c8d00;
76: lVar3 = *(long *)(lVar9 + 0x30);
77: *(long *)(lVar9 + 0x38) = lVar7;
78: lVar12 = 0x5b6900;
79: lVar10 = -0x80;
80: lVar9 = -0xb2f480;
81: lVar11 = -0xe25100;
82: do {
83: *(int *)(lVar1 + 0x200 + lVar10 * 4) = (int)((ulong)lVar9 >> 0x10);
84: *(int *)(lVar2 + 0x200 + lVar10 * 4) = (int)((ulong)lVar11 >> 0x10);
85: *(long *)(lVar3 + 0x400 + lVar10 * 8) = lVar12;
86: lVar12 = lVar12 + -0xb6d2;
87: *(long *)(lVar7 + 0x400 + lVar10 * 8) = lVar13;
88: lVar10 = lVar10 + 1;
89: lVar13 = lVar13 + -0x581a;
90: lVar9 = lVar9 + 0x166e9;
91: lVar11 = lVar11 + 0x1c5a2;
92: } while (lVar10 != 0x80);
93: return;
94: }
95: 
