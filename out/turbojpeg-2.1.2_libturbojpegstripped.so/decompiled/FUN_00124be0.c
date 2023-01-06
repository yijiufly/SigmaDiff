1: 
2: void FUN_00124be0(long param_1,code **param_2)
3: 
4: {
5: int iVar1;
6: uint uVar2;
7: code **ppcVar3;
8: long lVar4;
9: undefined4 uVar5;
10: undefined4 uVar6;
11: undefined4 uVar7;
12: undefined4 *puVar8;
13: undefined4 *puVar9;
14: long lVar10;
15: long lVar11;
16: int iStack76;
17: undefined4 *puStack64;
18: 
19: iVar1 = *(int *)((long)param_2 + 0x24);
20: if (iVar1 != 100) {
21: ppcVar3 = (code **)*param_2;
22: *(undefined4 *)(ppcVar3 + 5) = 0x14;
23: *(int *)((long)ppcVar3 + 0x2c) = iVar1;
24: (**ppcVar3)(param_2);
25: }
26: lVar10 = 0;
27: *(undefined4 *)(param_2 + 6) = *(undefined4 *)(param_1 + 0x30);
28: *(undefined4 *)((long)param_2 + 0x34) = *(undefined4 *)(param_1 + 0x34);
29: *(undefined4 *)(param_2 + 7) = *(undefined4 *)(param_1 + 0x38);
30: *(undefined4 *)((long)param_2 + 0x3c) = *(undefined4 *)(param_1 + 0x3c);
31: FUN_0011fa80(param_2);
32: FUN_0011f6f0(param_2,*(undefined4 *)(param_1 + 0x3c));
33: *(undefined4 *)(param_2 + 9) = *(undefined4 *)(param_1 + 0x128);
34: *(undefined4 *)((long)param_2 + 0x10c) = *(undefined4 *)(param_1 + 0x188);
35: do {
36: puVar9 = *(undefined4 **)(param_1 + 200 + lVar10);
37: if (puVar9 != (undefined4 *)0x0) {
38: puVar8 = *(undefined4 **)((long)param_2 + lVar10 + 0x60);
39: if (puVar8 == (undefined4 *)0x0) {
40: puVar8 = (undefined4 *)FUN_0011f510(param_2);
41: *(undefined4 **)((long)param_2 + lVar10 + 0x60) = puVar8;
42: puVar9 = *(undefined4 **)(param_1 + 200 + lVar10);
43: }
44: uVar5 = puVar9[1];
45: uVar6 = puVar9[2];
46: uVar7 = puVar9[3];
47: *puVar8 = *puVar9;
48: puVar8[1] = uVar5;
49: puVar8[2] = uVar6;
50: puVar8[3] = uVar7;
51: uVar5 = puVar9[5];
52: uVar6 = puVar9[6];
53: uVar7 = puVar9[7];
54: puVar8[4] = puVar9[4];
55: puVar8[5] = uVar5;
56: puVar8[6] = uVar6;
57: puVar8[7] = uVar7;
58: uVar5 = puVar9[9];
59: uVar6 = puVar9[10];
60: uVar7 = puVar9[0xb];
61: puVar8[8] = puVar9[8];
62: puVar8[9] = uVar5;
63: puVar8[10] = uVar6;
64: puVar8[0xb] = uVar7;
65: uVar5 = puVar9[0xd];
66: uVar6 = puVar9[0xe];
67: uVar7 = puVar9[0xf];
68: puVar8[0xc] = puVar9[0xc];
69: puVar8[0xd] = uVar5;
70: puVar8[0xe] = uVar6;
71: puVar8[0xf] = uVar7;
72: uVar5 = puVar9[0x11];
73: uVar6 = puVar9[0x12];
74: uVar7 = puVar9[0x13];
75: puVar8[0x10] = puVar9[0x10];
76: puVar8[0x11] = uVar5;
77: puVar8[0x12] = uVar6;
78: puVar8[0x13] = uVar7;
79: uVar5 = puVar9[0x15];
80: uVar6 = puVar9[0x16];
81: uVar7 = puVar9[0x17];
82: puVar8[0x14] = puVar9[0x14];
83: puVar8[0x15] = uVar5;
84: puVar8[0x16] = uVar6;
85: puVar8[0x17] = uVar7;
86: uVar5 = puVar9[0x19];
87: uVar6 = puVar9[0x1a];
88: uVar7 = puVar9[0x1b];
89: puVar8[0x18] = puVar9[0x18];
90: puVar8[0x19] = uVar5;
91: puVar8[0x1a] = uVar6;
92: puVar8[0x1b] = uVar7;
93: *(undefined (*) [16])(puVar8 + 0x1c) = *(undefined (*) [16])(puVar9 + 0x1c);
94: *(undefined4 *)(*(long *)((long)param_2 + lVar10 + 0x60) + 0x80) = 0;
95: }
96: lVar10 = lVar10 + 8;
97: } while (lVar10 != 0x20);
98: iVar1 = *(int *)(param_1 + 0x38);
99: *(int *)((long)param_2 + 0x4c) = iVar1;
100: if (iVar1 - 1U < 10) {
101: puStack64 = (undefined4 *)param_2[0xb];
102: puVar9 = *(undefined4 **)(param_1 + 0x130);
103: }
104: else {
105: ppcVar3 = (code **)*param_2;
106: *(undefined4 *)(ppcVar3 + 5) = 0x1a;
107: *(int *)((long)ppcVar3 + 0x2c) = iVar1;
108: *(undefined4 *)(ppcVar3 + 6) = 10;
109: (**ppcVar3)(param_2);
110: puStack64 = (undefined4 *)param_2[0xb];
111: puVar9 = *(undefined4 **)(param_1 + 0x130);
112: if (*(int *)((long)param_2 + 0x4c) < 1) goto LAB_00124dd8;
113: }
114: iStack76 = 0;
115: do {
116: *puStack64 = *puVar9;
117: puStack64[2] = puVar9[2];
118: puStack64[3] = puVar9[3];
119: uVar2 = puVar9[4];
120: puStack64[4] = uVar2;
121: if ((3 < uVar2) || (lVar10 = *(long *)(param_1 + 200 + (long)(int)uVar2 * 8), lVar10 == 0)) {
122: ppcVar3 = (code **)*param_2;
123: *(undefined4 *)(ppcVar3 + 5) = 0x34;
124: *(uint *)((long)ppcVar3 + 0x2c) = uVar2;
125: (**ppcVar3)(param_2);
126: lVar10 = *(long *)(param_1 + 200 + (long)(int)uVar2 * 8);
127: }
128: lVar4 = *(long *)(puVar9 + 0x14);
129: if (lVar4 != 0) {
130: lVar11 = 0;
131: do {
132: if (*(short *)(lVar4 + lVar11) != *(short *)(lVar10 + lVar11)) {
133: ppcVar3 = (code **)*param_2;
134: *(undefined4 *)(ppcVar3 + 5) = 0x2c;
135: *(uint *)((long)ppcVar3 + 0x2c) = uVar2;
136: (**ppcVar3)(param_2);
137: }
138: lVar11 = lVar11 + 2;
139: } while (lVar11 != 0x80);
140: }
141: iStack76 = iStack76 + 1;
142: puVar9 = puVar9 + 0x18;
143: puStack64 = puStack64 + 0x18;
144: } while (*(int *)((long)param_2 + 0x4c) != iStack76 && iStack76 <= *(int *)((long)param_2 + 0x4c))
145: ;
146: LAB_00124dd8:
147: if (*(int *)(param_1 + 0x174) != 0) {
148: if (*(char *)(param_1 + 0x178) == '\x01') {
149: *(undefined *)((long)param_2 + 0x124) = 1;
150: *(undefined *)((long)param_2 + 0x125) = *(undefined *)(param_1 + 0x179);
151: }
152: *(undefined *)((long)param_2 + 0x126) = *(undefined *)(param_1 + 0x17a);
153: *(undefined2 *)(param_2 + 0x25) = *(undefined2 *)(param_1 + 0x17c);
154: *(undefined2 *)((long)param_2 + 0x12a) = *(undefined2 *)(param_1 + 0x17e);
155: }
156: return;
157: }
158: 
