1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: undefined8 FUN_00140bd0(long *param_1,long param_2)
5: 
6: {
7: long lVar1;
8: int iVar2;
9: int iVar3;
10: uint uVar4;
11: int iVar5;
12: long lVar6;
13: long lVar7;
14: short sVar8;
15: long lVar9;
16: long lVar10;
17: uint uVar11;
18: long lVar12;
19: long lStack112;
20: undefined2 *puStack96;
21: 
22: lVar1 = param_1[0x4a];
23: if (*(int *)(param_1 + 0x2e) != 0) {
24: iVar2 = *(int *)(lVar1 + 0x4c);
25: if (iVar2 == 0) {
26: FUN_00140730(param_1);
27: iVar2 = *(int *)(lVar1 + 0x4c);
28: }
29: *(int *)(lVar1 + 0x4c) = iVar2 + -1;
30: }
31: if ((*(int *)(lVar1 + 0x28) != -1) && (0 < *(int *)(param_1 + 0x3c))) {
32: lStack112 = 0;
33: do {
34: if (param_2 == 0) {
35: puStack96 = (undefined2 *)0x0;
36: }
37: else {
38: puStack96 = *(undefined2 **)(param_2 + lStack112 * 8);
39: }
40: lVar6 = (long)*(int *)((long)param_1 + lStack112 * 4 + 0x1e4);
41: lVar10 = param_1[lVar6 + 0x37];
42: lVar6 = lVar1 + lVar6 * 4;
43: lVar12 = (long)*(int *)(lVar10 + 0x14);
44: lVar7 = lVar1 + lVar12 * 8;
45: lVar9 = (long)*(int *)(lVar6 + 0x3c) + *(long *)(lVar7 + 0x50);
46: iVar2 = FUN_00140970(param_1,lVar9);
47: if (iVar2 == 0) {
48: *(undefined4 *)(lVar6 + 0x3c) = 0;
49: }
50: else {
51: iVar2 = FUN_00140970(param_1,lVar9 + 1);
52: lVar9 = lVar9 + 2 + (long)iVar2;
53: uVar4 = FUN_00140970(param_1,lVar9);
54: if (uVar4 != 0) {
55: lVar9 = *(long *)(lVar7 + 0x50) + 0x14;
56: while (iVar3 = FUN_00140970(param_1,lVar9), iVar3 != 0) {
57: uVar4 = uVar4 * 2;
58: if (uVar4 == 0x8000) {
59: LAB_00140e58:
60: lVar6 = *param_1;
61: *(undefined4 *)(lVar6 + 0x28) = 0x7e;
62: (**(code **)(lVar6 + 8))(param_1,0xffffffff);
63: *(undefined4 *)(lVar1 + 0x28) = 0xffffffff;
64: return 1;
65: }
66: lVar9 = lVar9 + 1;
67: }
68: }
69: if ((int)uVar4 < (int)((1 << (*(byte *)((long)param_1 + lVar12 + 0x140) & 0x3f)) >> 1)) {
70: *(undefined4 *)(lVar6 + 0x3c) = 0;
71: }
72: else {
73: if ((int)((1 << (*(byte *)((long)param_1 + lVar12 + 0x150) & 0x3f)) >> 1) < (int)uVar4) {
74: *(int *)(lVar6 + 0x3c) = iVar2 * 4 + 0xc;
75: }
76: else {
77: *(int *)(lVar6 + 0x3c) = iVar2 * 4 + 4;
78: }
79: }
80: uVar11 = uVar4;
81: while (uVar4 = (int)uVar4 >> 1, uVar4 != 0) {
82: iVar3 = FUN_00140970(param_1,lVar9 + 0xe);
83: if (iVar3 != 0) {
84: uVar11 = uVar11 | uVar4;
85: }
86: }
87: iVar3 = -(uVar11 + 1);
88: if (iVar2 == 0) {
89: iVar3 = uVar11 + 1;
90: }
91: *(uint *)(lVar6 + 0x2c) = iVar3 + *(int *)(lVar6 + 0x2c) & 0xffff;
92: }
93: if (puStack96 != (undefined2 *)0x0) {
94: *puStack96 = (short)*(undefined4 *)(lVar6 + 0x2c);
95: }
96: iVar2 = 1;
97: lVar7 = (long)*(int *)(lVar10 + 0x18);
98: lVar6 = lVar1 + lVar7 * 8;
99: do {
100: lVar10 = (long)(iVar2 * 3 + -3) + *(long *)(lVar6 + 0xd0);
101: iVar3 = FUN_00140970(param_1,lVar10);
102: if (iVar3 != 0) break;
103: while (iVar3 = FUN_00140970(param_1,lVar10 + 1), iVar3 == 0) {
104: iVar2 = iVar2 + 1;
105: lVar10 = lVar10 + 3;
106: if (0x3f < iVar2) goto LAB_00140e58;
107: }
108: lVar10 = lVar10 + 2;
109: iVar3 = FUN_00140970(param_1,lVar1 + 0x150);
110: uVar4 = FUN_00140970(param_1,lVar10);
111: if ((uVar4 != 0) && (iVar5 = FUN_00140970(param_1,lVar10), iVar5 != 0)) {
112: uVar4 = uVar4 * 2;
113: lVar10 = 0xbd;
114: if ((int)(uint)*(byte *)((long)param_1 + lVar7 + 0x160) < iVar2) {
115: lVar10 = 0xd9;
116: }
117: lVar10 = lVar10 + *(long *)(lVar6 + 0xd0);
118: while (iVar5 = FUN_00140970(param_1,lVar10), iVar5 != 0) {
119: uVar4 = uVar4 * 2;
120: if (uVar4 == 0x8000) goto LAB_00140e58;
121: lVar10 = lVar10 + 1;
122: }
123: }
124: uVar11 = uVar4;
125: while (uVar4 = (int)uVar4 >> 1, uVar4 != 0) {
126: iVar5 = FUN_00140970(param_1,lVar10 + 0xe);
127: if (iVar5 != 0) {
128: uVar11 = uVar11 | uVar4;
129: }
130: }
131: sVar8 = (short)uVar11 + 1;
132: if (iVar3 != 0) {
133: sVar8 = -sVar8;
134: }
135: if (puStack96 != (undefined2 *)0x0) {
136: puStack96[*(int *)(&DAT_0018b460 + (long)iVar2 * 4)] = sVar8;
137: }
138: iVar2 = iVar2 + 1;
139: } while (iVar2 < 0x40);
140: lStack112 = lStack112 + 1;
141: } while (*(int *)(param_1 + 0x3c) != (int)lStack112 + 1 &&
142: (int)lStack112 + 1 <= *(int *)(param_1 + 0x3c));
143: }
144: return 1;
145: }
146: 
