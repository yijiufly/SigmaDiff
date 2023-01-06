1: 
2: void FUN_0014a640(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined4 uVar3;
8: uint uVar4;
9: code *pcVar5;
10: code **ppcVar6;
11: undefined8 *puVar7;
12: undefined (*pauVar8) [16];
13: ulong uVar9;
14: long lVar10;
15: long lVar11;
16: code *pcVar12;
17: byte bVar13;
18: 
19: bVar13 = 0;
20: pcVar5 = param_1[0x3e];
21: if (param_2 != 0) {
22: ppcVar6 = (code **)*param_1;
23: *(undefined4 *)(ppcVar6 + 5) = 0x30;
24: (**ppcVar6)();
25: }
26: iVar1 = *(int *)((long)param_1 + 0x134);
27: if (iVar1 == 0) {
28: *(code **)(pcVar5 + 8) = FUN_0014c2f0;
29: }
30: else {
31: if (*(int *)((long)param_1 + 0x1a4) == 0) {
32: if (*(int *)((long)param_1 + 0x19c) == 0) {
33: iVar2 = *(int *)((long)param_1 + 0x144);
34: *(code **)(pcVar5 + 8) = FUN_0014b9b0;
35: goto joined_r0x0014a713;
36: }
37: *(code **)(pcVar5 + 8) = FUN_0014bc50;
38: }
39: else {
40: if (*(int *)((long)param_1 + 0x19c) == 0) {
41: *(code **)(pcVar5 + 8) = FUN_0014bf90;
42: }
43: else {
44: *(code **)(pcVar5 + 8) = FUN_0014c040;
45: }
46: }
47: }
48: iVar2 = *(int *)((long)param_1 + 0x144);
49: joined_r0x0014a713:
50: if (0 < iVar2) {
51: lVar10 = 1;
52: pcVar12 = param_1[0x29];
53: if (iVar1 == 0) goto LAB_0014a7ed;
54: LAB_0014a72d:
55: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0))
56: goto LAB_0014a7ed;
57: do {
58: lVar11 = lVar10;
59: if (*(int *)(param_1 + 0x34) == 0) goto LAB_0014a7c4;
60: do {
61: uVar4 = *(uint *)(pcVar12 + 0x18);
62: if (0xf < uVar4) {
63: ppcVar6 = (code **)*param_1;
64: *(undefined4 *)(ppcVar6 + 5) = 0x7d;
65: *(uint *)((long)ppcVar6 + 0x2c) = uVar4;
66: (**ppcVar6)(param_1);
67: }
68: puVar7 = *(undefined8 **)(pcVar5 + (long)(int)uVar4 * 8 + 0xe8);
69: if (puVar7 == (undefined8 *)0x0) {
70: puVar7 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x100);
71: *(undefined8 **)(pcVar5 + (long)(int)uVar4 * 8 + 0xe8) = puVar7;
72: }
73: *puVar7 = 0;
74: puVar7[0x1f] = 0;
75: uVar9 = (ulong)(((int)puVar7 - (int)(undefined8 *)((ulong)(puVar7 + 1) & 0xfffffffffffffff8)
76: ) + 0x100U >> 3);
77: puVar7 = (undefined8 *)((ulong)(puVar7 + 1) & 0xfffffffffffffff8);
78: while (lVar11 = lVar10, uVar9 != 0) {
79: uVar9 = uVar9 - 1;
80: *puVar7 = 0;
81: puVar7 = puVar7 + (ulong)bVar13 * -2 + 1;
82: }
83: LAB_0014a7c4:
84: lVar10 = lVar11 + 1;
85: if (*(int *)((long)param_1 + 0x144) == (int)lVar11 ||
86: *(int *)((long)param_1 + 0x144) < (int)lVar11) goto LAB_0014a6a9;
87: pcVar12 = param_1[lVar11 + 0x29];
88: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0014a72d;
89: LAB_0014a7ed:
90: uVar4 = *(uint *)(pcVar12 + 0x14);
91: if (0xf < uVar4) {
92: ppcVar6 = (code **)*param_1;
93: *(undefined4 *)(ppcVar6 + 5) = 0x7d;
94: *(uint *)((long)ppcVar6 + 0x2c) = uVar4;
95: (**ppcVar6)(param_1);
96: }
97: pauVar8 = *(undefined (**) [16])(pcVar5 + (long)(int)uVar4 * 8 + 0x68);
98: if (pauVar8 == (undefined (*) [16])0x0) {
99: pauVar8 = (undefined (*) [16])(**(code **)param_1[1])(param_1,1,0x40);
100: *(undefined (**) [16])(pcVar5 + (long)(int)uVar4 * 8 + 0x68) = pauVar8;
101: }
102: *pauVar8 = (undefined  [16])0x0;
103: pauVar8[1] = (undefined  [16])0x0;
104: pauVar8[2] = (undefined  [16])0x0;
105: pauVar8[3] = (undefined  [16])0x0;
106: *(undefined4 *)(pcVar5 + lVar10 * 4 + 0x3c) = 0;
107: *(undefined4 *)(pcVar5 + lVar10 * 4 + 0x4c) = 0;
108: } while (*(int *)((long)param_1 + 0x134) == 0);
109: } while( true );
110: }
111: LAB_0014a6a9:
112: *(undefined8 *)(pcVar5 + 0x30) = 0;
113: *(undefined8 *)(pcVar5 + 0x18) = 0;
114: *(undefined8 *)(pcVar5 + 0x38) = 0xffffffff0000000b;
115: uVar3 = *(undefined4 *)(param_1 + 0x23);
116: *(undefined8 *)(pcVar5 + 0x20) = 0x10000;
117: *(undefined8 *)(pcVar5 + 0x28) = 0;
118: *(undefined4 *)(pcVar5 + 100) = 0;
119: *(undefined4 *)(pcVar5 + 0x60) = uVar3;
120: return;
121: }
122: 
