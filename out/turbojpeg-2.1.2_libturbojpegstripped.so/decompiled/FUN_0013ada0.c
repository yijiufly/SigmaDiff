1: 
2: void FUN_0013ada0(long param_1)
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
22: *ppcVar5 = FUN_001386a0;
23: iVar4 = *(int *)(param_1 + 0x19c);
24: *(int *)((long)ppcVar5 + 0x4c) = *(int *)(param_1 + 0x88) * *(int *)(param_1 + 0x90);
25: if (iVar4 == 2) {
26: ppcVar5[1] = FUN_0013ac90;
27: iVar4 = FUN_0016c070();
28: if (iVar4 == 0) {
29: iVar4 = *(int *)(param_1 + 0x40);
30: ppcVar5[3] = FUN_00139020;
31: }
32: else {
33: iVar4 = *(int *)(param_1 + 0x40);
34: ppcVar5[3] = FUN_0016c090;
35: }
36: if (iVar4 == 0x10) {
37: if (*(int *)(param_1 + 0x70) == 0) {
38: ppcVar5[3] = FUN_0013a570;
39: }
40: else {
41: ppcVar5[3] = FUN_0013a890;
42: }
43: }
44: pcVar8 = (code *)(**(code **)(*(long *)(param_1 + 8) + 8))
45: (param_1,1,*(undefined4 *)((long)ppcVar5 + 0x4c));
46: ppcVar5[8] = pcVar8;
47: }
48: else {
49: ppcVar5[1] = FUN_001386c0;
50: iVar4 = FUN_0016c080();
51: if (iVar4 == 0) {
52: iVar4 = *(int *)(param_1 + 0x40);
53: ppcVar5[3] = FUN_001386f0;
54: }
55: else {
56: iVar4 = *(int *)(param_1 + 0x40);
57: ppcVar5[3] = FUN_0016c0a0;
58: }
59: if (iVar4 == 0x10) {
60: if (*(int *)(param_1 + 0x70) == 0) {
61: ppcVar5[3] = FUN_0013a110;
62: }
63: else {
64: ppcVar5[3] = FUN_0013a2e0;
65: }
66: }
67: ppcVar5[8] = (code *)0x0;
68: }
69: lVar9 = *(long *)(param_1 + 0x260);
70: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
71: *(undefined8 *)(lVar9 + 0x20) = uVar6;
72: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x400);
73: *(undefined8 *)(lVar9 + 0x28) = uVar6;
74: uVar6 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
75: *(undefined8 *)(lVar9 + 0x30) = uVar6;
76: lVar7 = (***(code ***)(param_1 + 8))(param_1,1,0x800);
77: lVar1 = *(long *)(lVar9 + 0x20);
78: lVar2 = *(long *)(lVar9 + 0x28);
79: lVar13 = 0x2c8d00;
80: lVar3 = *(long *)(lVar9 + 0x30);
81: *(long *)(lVar9 + 0x38) = lVar7;
82: lVar12 = 0x5b6900;
83: lVar10 = -0x80;
84: lVar9 = -0xb2f480;
85: lVar11 = -0xe25100;
86: do {
87: *(int *)(lVar1 + 0x200 + lVar10 * 4) = (int)((ulong)lVar9 >> 0x10);
88: *(int *)(lVar2 + 0x200 + lVar10 * 4) = (int)((ulong)lVar11 >> 0x10);
89: *(long *)(lVar3 + 0x400 + lVar10 * 8) = lVar12;
90: lVar12 = lVar12 + -0xb6d2;
91: *(long *)(lVar7 + 0x400 + lVar10 * 8) = lVar13;
92: lVar10 = lVar10 + 1;
93: lVar13 = lVar13 + -0x581a;
94: lVar9 = lVar9 + 0x166e9;
95: lVar11 = lVar11 + 0x1c5a2;
96: } while (lVar10 != 0x80);
97: return;
98: }
99: 
