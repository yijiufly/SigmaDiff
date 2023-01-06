1: 
2: undefined8 FUN_0014b4a0(long param_1,byte *param_2)
3: 
4: {
5: ushort *puVar1;
6: ushort **ppuVar2;
7: byte bVar3;
8: int iVar4;
9: undefined4 uVar5;
10: byte *pbVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: 
14: *(undefined4 *)(param_1 + 0x10) = 0;
15: *(undefined4 *)(param_1 + 0x1c) = 0;
16: *(undefined4 *)(param_1 + 0x24) = 0;
17: *(undefined4 *)(param_1 + 0x2c) = 0;
18: *(undefined4 *)(param_1 + 0x34) = 0;
19: ppuVar2 = __ctype_b_loc();
20: bVar3 = *param_2;
21: puVar1 = *ppuVar2;
22: pbVar8 = param_2;
23: if ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) != 0) {
24: iVar4 = 0;
25: do {
26: pbVar7 = pbVar8;
27: pbVar8 = pbVar7 + 1;
28: iVar4 = (char)bVar3 + -0x30 + iVar4 * 10;
29: bVar3 = pbVar7[1];
30: } while ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) != 0);
31: *(int *)(param_1 + 0x18) = iVar4;
32: if (pbVar8 == param_2) {
33: return 0;
34: }
35: if ((*pbVar8 & 0xdf) == 0x46) {
36: *(undefined4 *)(param_1 + 0x1c) = 3;
37: pbVar8 = pbVar7 + 2;
38: bVar3 = pbVar7[2];
39: }
40: else {
41: *(undefined4 *)(param_1 + 0x1c) = 1;
42: bVar3 = pbVar7[1];
43: }
44: }
45: if ((bVar3 & 0xdf) == 0x58) {
46: bVar3 = pbVar8[1];
47: pbVar7 = pbVar8 + 1;
48: if ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) == 0) {
49: *(undefined4 *)(param_1 + 0x20) = 0;
50: return 0;
51: }
52: iVar4 = 0;
53: pbVar8 = pbVar7;
54: do {
55: pbVar6 = pbVar8;
56: pbVar8 = pbVar6 + 1;
57: iVar4 = (char)bVar3 + -0x30 + iVar4 * 10;
58: bVar3 = pbVar6[1];
59: } while ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) != 0);
60: *(int *)(param_1 + 0x20) = iVar4;
61: if (pbVar8 == pbVar7) {
62: return 0;
63: }
64: if ((*pbVar8 & 0xdf) == 0x46) {
65: *(undefined4 *)(param_1 + 0x24) = 3;
66: pbVar8 = pbVar6 + 2;
67: bVar3 = pbVar6[2];
68: }
69: else {
70: *(undefined4 *)(param_1 + 0x24) = 1;
71: bVar3 = pbVar6[1];
72: }
73: }
74: if (bVar3 == 0x2d) {
75: uVar5 = 2;
76: }
77: else {
78: uVar5 = 1;
79: if (bVar3 != 0x2b) goto joined_r0x0014b5e0;
80: }
81: *(undefined4 *)(param_1 + 0x2c) = uVar5;
82: bVar3 = pbVar8[1];
83: if ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) == 0) {
84: *(undefined4 *)(param_1 + 0x28) = 0;
85: return 0;
86: }
87: iVar4 = 0;
88: pbVar7 = pbVar8 + 1;
89: do {
90: pbVar6 = pbVar7;
91: pbVar7 = pbVar6 + 1;
92: iVar4 = (char)bVar3 + -0x30 + iVar4 * 10;
93: bVar3 = *pbVar7;
94: } while ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) != 0);
95: *(int *)(param_1 + 0x28) = iVar4;
96: if (pbVar7 == pbVar8 + 1) {
97: return 0;
98: }
99: bVar3 = *pbVar7;
100: if (bVar3 == 0x2d) {
101: uVar5 = 2;
102: }
103: else {
104: if (bVar3 != 0x2b) goto joined_r0x0014b5e0;
105: uVar5 = 1;
106: }
107: *(undefined4 *)(param_1 + 0x34) = uVar5;
108: bVar3 = pbVar6[2];
109: if ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) == 0) {
110: *(undefined4 *)(param_1 + 0x30) = 0;
111: return 0;
112: }
113: iVar4 = 0;
114: pbVar8 = pbVar6 + 2;
115: do {
116: pbVar7 = pbVar8;
117: iVar4 = (char)bVar3 + -0x30 + iVar4 * 10;
118: bVar3 = pbVar7[1];
119: pbVar8 = pbVar7 + 1;
120: } while ((*(byte *)((long)puVar1 + (long)(char)bVar3 * 2 + 1) & 8) != 0);
121: *(int *)(param_1 + 0x30) = iVar4;
122: if (pbVar7 + 1 == pbVar6 + 2) {
123: return 0;
124: }
125: bVar3 = pbVar7[1];
126: joined_r0x0014b5e0:
127: if (bVar3 != 0) {
128: return 0;
129: }
130: *(undefined4 *)(param_1 + 0x10) = 1;
131: return 1;
132: }
133: 
