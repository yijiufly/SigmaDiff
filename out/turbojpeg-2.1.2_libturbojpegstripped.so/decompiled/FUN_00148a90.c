1: 
2: long FUN_00148a90(code **param_1,uint param_2,ulong param_3)
3: 
4: {
5: long *plVar1;
6: code *pcVar2;
7: code *pcVar3;
8: code **ppcVar4;
9: undefined8 *puVar5;
10: long lVar6;
11: undefined8 *puVar7;
12: ulong uVar8;
13: ulong uVar9;
14: ulong uVar10;
15: ulong uVar11;
16: 
17: pcVar3 = param_1[1];
18: if (1000000000 < param_3) {
19: ppcVar4 = (code **)*param_1;
20: ppcVar4[5] = (code *)0x700000036;
21: (**ppcVar4)();
22: }
23: uVar10 = param_3 + 0x1f & 0xffffffffffffffe0;
24: uVar11 = uVar10 + 0x37;
25: if (1000000000 < uVar11) {
26: ppcVar4 = (code **)*param_1;
27: ppcVar4[5] = (code *)0x100000036;
28: (**ppcVar4)(param_1);
29: }
30: if (1 < param_2) {
31: ppcVar4 = (code **)*param_1;
32: *(undefined4 *)(ppcVar4 + 5) = 0xe;
33: *(uint *)((long)ppcVar4 + 0x2c) = param_2;
34: (**ppcVar4)(param_1);
35: }
36: lVar6 = (long)(int)param_2;
37: pcVar2 = pcVar3 + lVar6 * 8;
38: puVar5 = *(undefined8 **)(pcVar2 + 0x68);
39: puVar7 = puVar5;
40: if (puVar5 == (undefined8 *)0x0) {
41: uVar9 = *(ulong *)(&DAT_0018f260 + lVar6 * 8);
42: LAB_00148b5f:
43: uVar8 = 1000000000 - uVar11;
44: if (uVar9 < 1000000000 - uVar11) {
45: uVar8 = uVar9;
46: }
47: while( true ) {
48: puVar5 = (undefined8 *)FUN_0014a5a0(param_1,uVar11 + uVar8);
49: if (puVar5 != (undefined8 *)0x0) break;
50: uVar8 = uVar8 >> 1;
51: if (uVar8 < 0x32) {
52: ppcVar4 = (code **)*param_1;
53: ppcVar4[5] = (code *)0x200000036;
54: (**ppcVar4)(param_1);
55: }
56: }
57: uVar9 = uVar8 + uVar10;
58: plVar1 = (long *)(pcVar3 + 0x98);
59: *plVar1 = *plVar1 + uVar11 + uVar8;
60: *puVar5 = 0;
61: puVar5[1] = 0;
62: puVar5[2] = uVar9;
63: uVar11 = uVar10;
64: if (puVar7 == (undefined8 *)0x0) {
65: *(undefined8 **)(pcVar2 + 0x68) = puVar5;
66: lVar6 = 0;
67: }
68: else {
69: *puVar7 = puVar5;
70: lVar6 = 0;
71: }
72: }
73: else {
74: uVar9 = puVar5[2];
75: if (uVar9 < uVar10) {
76: do {
77: puVar5 = (undefined8 *)*puVar7;
78: if (puVar5 == (undefined8 *)0x0) {
79: uVar9 = *(ulong *)(&DAT_0018f250 + lVar6 * 8);
80: goto LAB_00148b5f;
81: }
82: uVar9 = puVar5[2];
83: puVar7 = puVar5;
84: } while (uVar9 < uVar10);
85: lVar6 = puVar5[1];
86: uVar11 = uVar10 + lVar6;
87: }
88: else {
89: lVar6 = puVar5[1];
90: uVar11 = uVar10 + lVar6;
91: }
92: }
93: puVar7 = puVar5 + 3;
94: if (((ulong)puVar7 & 0x1f) != 0) {
95: puVar7 = (undefined8 *)((long)puVar7 + (0x20 - (ulong)((uint)puVar7 & 0x1f)));
96: }
97: puVar5[1] = uVar11;
98: puVar5[2] = uVar9 - uVar10;
99: return (long)puVar7 + lVar6;
100: }
101: 
