1: 
2: undefined8 FUN_00159920(long param_1,byte *param_2)
3: 
4: {
5: ushort *puVar1;
6: byte bVar2;
7: uint uVar3;
8: ushort **ppuVar4;
9: ulong uVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: int iVar8;
13: byte *pbVar9;
14: 
15: *(undefined4 *)(param_1 + 0x10) = 0;
16: *(undefined4 *)(param_1 + 0x1c) = 0;
17: *(undefined4 *)(param_1 + 0x24) = 0;
18: *(undefined4 *)(param_1 + 0x2c) = 0;
19: *(undefined4 *)(param_1 + 0x34) = 0;
20: ppuVar4 = __ctype_b_loc();
21: uVar5 = SEXT18((char)*param_2);
22: puVar1 = *ppuVar4;
23: pbVar7 = param_2;
24: if ((*(byte *)((long)puVar1 + uVar5 * 2 + 1) & 8) != 0) {
25: iVar8 = 0;
26: do {
27: pbVar9 = pbVar7;
28: pbVar7 = pbVar9 + 1;
29: iVar8 = (int)uVar5 + -0x30 + iVar8 * 10;
30: uVar5 = (ulong)(uint)(int)(char)pbVar9[1];
31: } while ((*(byte *)((long)puVar1 + (long)(char)pbVar9[1] * 2 + 1) & 8) != 0);
32: *(int *)(param_1 + 0x18) = iVar8;
33: if (pbVar7 == param_2) {
34: return 0;
35: }
36: if ((*pbVar7 & 0xdf) == 0x46) {
37: *(undefined4 *)(param_1 + 0x1c) = 3;
38: pbVar7 = pbVar9 + 2;
39: uVar5 = (ulong)pbVar9[2];
40: }
41: else {
42: if ((*pbVar7 & 0xdf) == 0x52) {
43: *(undefined4 *)(param_1 + 0x1c) = 4;
44: pbVar7 = pbVar9 + 2;
45: uVar5 = (ulong)pbVar9[2];
46: }
47: else {
48: *(undefined4 *)(param_1 + 0x1c) = 1;
49: uVar5 = (ulong)pbVar9[1];
50: }
51: }
52: }
53: uVar3 = (uint)uVar5;
54: if (((byte)uVar5 & 0xdf) == 0x58) {
55: uVar5 = SEXT18((char)pbVar7[1]);
56: pbVar9 = pbVar7 + 1;
57: if ((*(byte *)((long)puVar1 + uVar5 * 2 + 1) & 8) == 0) {
58: *(undefined4 *)(param_1 + 0x20) = 0;
59: return 0;
60: }
61: iVar8 = 0;
62: pbVar7 = pbVar9;
63: do {
64: pbVar6 = pbVar7;
65: pbVar7 = pbVar6 + 1;
66: iVar8 = (int)uVar5 + -0x30 + iVar8 * 10;
67: uVar5 = (ulong)(uint)(int)(char)pbVar6[1];
68: } while ((*(byte *)((long)puVar1 + (long)(char)pbVar6[1] * 2 + 1) & 8) != 0);
69: *(int *)(param_1 + 0x20) = iVar8;
70: if (pbVar9 == pbVar7) {
71: return 0;
72: }
73: if ((*pbVar7 & 0xdf) == 0x46) {
74: *(undefined4 *)(param_1 + 0x24) = 3;
75: pbVar7 = pbVar6 + 2;
76: uVar3 = (uint)pbVar6[2];
77: }
78: else {
79: if ((*pbVar7 & 0xdf) == 0x52) {
80: *(undefined4 *)(param_1 + 0x24) = 4;
81: pbVar7 = pbVar6 + 2;
82: uVar3 = (uint)pbVar6[2];
83: }
84: else {
85: *(undefined4 *)(param_1 + 0x24) = 1;
86: uVar3 = (uint)pbVar6[1];
87: }
88: }
89: }
90: bVar2 = (byte)uVar3;
91: if ((uVar3 - 0x2b & 0xfd) == 0) {
92: *(uint *)(param_1 + 0x2c) = (bVar2 == 0x2d) + 1;
93: uVar5 = SEXT18((char)pbVar7[1]);
94: if ((*(byte *)((long)puVar1 + uVar5 * 2 + 1) & 8) == 0) {
95: *(undefined4 *)(param_1 + 0x28) = 0;
96: return 0;
97: }
98: iVar8 = 0;
99: pbVar9 = pbVar7 + 1;
100: do {
101: pbVar6 = pbVar9;
102: pbVar9 = pbVar6 + 1;
103: iVar8 = (int)uVar5 + -0x30 + iVar8 * 10;
104: uVar5 = (ulong)(uint)(int)(char)pbVar6[1];
105: } while ((*(byte *)((long)puVar1 + (long)(char)pbVar6[1] * 2 + 1) & 8) != 0);
106: *(int *)(param_1 + 0x28) = iVar8;
107: if (pbVar7 + 1 == pbVar9) {
108: return 0;
109: }
110: bVar2 = *pbVar9;
111: if ((bVar2 - 0x2b & 0xfd) == 0) {
112: *(uint *)(param_1 + 0x34) = (bVar2 == 0x2d) + 1;
113: uVar5 = SEXT18((char)pbVar6[2]);
114: if ((*(byte *)((long)puVar1 + uVar5 * 2 + 1) & 8) == 0) {
115: *(undefined4 *)(param_1 + 0x30) = 0;
116: return 0;
117: }
118: iVar8 = 0;
119: pbVar7 = pbVar6 + 2;
120: do {
121: pbVar9 = pbVar7;
122: iVar8 = (int)uVar5 + -0x30 + iVar8 * 10;
123: uVar5 = (ulong)(uint)(int)(char)pbVar9[1];
124: pbVar7 = pbVar9 + 1;
125: } while ((*(byte *)((long)puVar1 + (long)(char)pbVar9[1] * 2 + 1) & 8) != 0);
126: *(int *)(param_1 + 0x30) = iVar8;
127: if (pbVar6 + 2 == pbVar9 + 1) {
128: return 0;
129: }
130: bVar2 = pbVar9[1];
131: }
132: }
133: if (bVar2 == 0) {
134: *(undefined4 *)(param_1 + 0x10) = 1;
135: return 1;
136: }
137: return 0;
138: }
139: 
