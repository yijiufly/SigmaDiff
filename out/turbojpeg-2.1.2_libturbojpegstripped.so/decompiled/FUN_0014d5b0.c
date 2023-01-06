1: 
2: undefined8 FUN_0014d5b0(long *param_1,long param_2)
3: 
4: {
5: long lVar1;
6: ushort uVar2;
7: int iVar3;
8: int iVar4;
9: uint uVar5;
10: int iVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: uint uVar11;
16: undefined2 *puStack104;
17: long lStack88;
18: 
19: lVar1 = param_1[0x4a];
20: if (*(int *)(param_1 + 0x2e) != 0) {
21: iVar3 = *(int *)(lVar1 + 0x4c);
22: if (iVar3 == 0) {
23: FUN_0014c910();
24: iVar3 = *(int *)(lVar1 + 0x4c);
25: }
26: *(int *)(lVar1 + 0x4c) = iVar3 + -1;
27: }
28: if ((*(int *)(lVar1 + 0x28) != -1) && (0 < *(int *)(param_1 + 0x3c))) {
29: lStack88 = 0;
30: do {
31: puStack104 = (undefined2 *)0x0;
32: if (param_2 != 0) {
33: puStack104 = *(undefined2 **)(param_2 + lStack88 * 8);
34: }
35: lVar7 = (long)*(int *)((long)param_1 + lStack88 * 4 + 0x1e4);
36: lVar9 = param_1[lVar7 + 0x37];
37: lVar7 = lVar1 + lVar7 * 4;
38: lVar10 = (long)*(int *)(lVar9 + 0x14);
39: lVar8 = (long)*(int *)(lVar7 + 0x3c) + *(long *)(lVar1 + lVar10 * 8 + 0x50);
40: iVar3 = FUN_0014cee0(param_1,lVar8);
41: if (iVar3 == 0) {
42: *(undefined4 *)(lVar7 + 0x3c) = 0;
43: }
44: else {
45: iVar3 = FUN_0014cee0(param_1,lVar8 + 1);
46: uVar5 = FUN_0014cee0(param_1);
47: if (uVar5 != 0) {
48: while (iVar4 = FUN_0014cee0(param_1), iVar4 != 0) {
49: uVar5 = uVar5 * 2;
50: if (uVar5 == 0x8000) {
51: LAB_0014d7c0:
52: lVar7 = *param_1;
53: *(undefined4 *)(lVar7 + 0x28) = 0x7e;
54: (**(code **)(lVar7 + 8))(param_1,0xffffffff);
55: *(undefined4 *)(lVar1 + 0x28) = 0xffffffff;
56: return 1;
57: }
58: }
59: }
60: uVar11 = uVar5;
61: if ((int)uVar5 < (int)((1 << (*(byte *)((long)param_1 + lVar10 + 0x140) & 0x3f)) >> 1)) {
62: *(undefined4 *)(lVar7 + 0x3c) = 0;
63: }
64: else {
65: if ((int)((1 << (*(byte *)((long)param_1 + lVar10 + 0x150) & 0x3f)) >> 1) < (int)uVar5) {
66: *(int *)(lVar7 + 0x3c) = iVar3 * 4 + 0xc;
67: }
68: else {
69: *(int *)(lVar7 + 0x3c) = iVar3 * 4 + 4;
70: }
71: }
72: while (uVar5 = (int)uVar5 >> 1, uVar5 != 0) {
73: iVar4 = FUN_0014cee0(param_1);
74: if (iVar4 != 0) {
75: uVar11 = uVar11 | uVar5;
76: }
77: }
78: uVar5 = uVar11 + 1;
79: if (iVar3 != 0) {
80: uVar5 = ~uVar11;
81: }
82: *(uint *)(lVar7 + 0x2c) = uVar5 + *(int *)(lVar7 + 0x2c) & 0xffff;
83: }
84: if (puStack104 != (undefined2 *)0x0) {
85: *puStack104 = (short)*(undefined4 *)(lVar7 + 0x2c);
86: }
87: lVar9 = (long)*(int *)(lVar9 + 0x18);
88: iVar3 = 1;
89: lVar7 = lVar1 + lVar9 * 8;
90: do {
91: lVar8 = (long)(iVar3 * 3 + -3) + *(long *)(lVar7 + 0xd0);
92: iVar4 = FUN_0014cee0(param_1,lVar8);
93: if (iVar4 != 0) break;
94: while (iVar4 = FUN_0014cee0(param_1,lVar8 + 1), iVar4 == 0) {
95: iVar3 = iVar3 + 1;
96: lVar8 = lVar8 + 3;
97: if (0x3f < iVar3) goto LAB_0014d7c0;
98: }
99: iVar4 = FUN_0014cee0(param_1,lVar1 + 0x150);
100: uVar5 = FUN_0014cee0(param_1,lVar8 + 2);
101: uVar11 = uVar5;
102: if ((uVar5 != 0) && (iVar6 = FUN_0014cee0(param_1,lVar8 + 2), iVar6 != 0)) {
103: uVar5 = uVar5 * 2;
104: lVar8 = 0xd9;
105: if (iVar3 <= (int)(uint)*(byte *)((long)param_1 + lVar9 + 0x160)) {
106: lVar8 = 0xbd;
107: }
108: lVar8 = lVar8 + *(long *)(lVar7 + 0xd0);
109: while (iVar6 = FUN_0014cee0(param_1,lVar8), uVar11 = uVar5, iVar6 != 0) {
110: uVar5 = uVar5 * 2;
111: if (uVar5 == 0x8000) goto LAB_0014d7c0;
112: lVar8 = lVar8 + 1;
113: }
114: }
115: while (uVar5 = (int)uVar5 >> 1, uVar5 != 0) {
116: iVar6 = FUN_0014cee0(param_1);
117: if (iVar6 != 0) {
118: uVar11 = uVar11 | uVar5;
119: }
120: }
121: uVar2 = ~(ushort)uVar11;
122: if (iVar4 == 0) {
123: uVar2 = (ushort)uVar11 + 1;
124: }
125: if (puStack104 != (undefined2 *)0x0) {
126: puStack104[*(int *)(&DAT_0018f100 + (long)iVar3 * 4)] = uVar2;
127: }
128: iVar3 = iVar3 + 1;
129: } while (iVar3 < 0x40);
130: iVar3 = (int)lStack88;
131: lStack88 = lStack88 + 1;
132: iVar3 = iVar3 + 1;
133: } while (*(int *)(param_1 + 0x3c) != iVar3 && iVar3 <= *(int *)(param_1 + 0x3c));
134: }
135: return 1;
136: }
137: 
