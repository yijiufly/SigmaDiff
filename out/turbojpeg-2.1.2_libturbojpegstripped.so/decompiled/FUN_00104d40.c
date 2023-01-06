1: 
2: void FUN_00104d40(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: byte bVar1;
6: int iVar2;
7: long lVar3;
8: undefined *puVar4;
9: byte **ppbVar5;
10: ulong uVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: byte *pbVar9;
14: undefined *puVar10;
15: undefined *puVar11;
16: 
17: iVar2 = *(int *)(param_1 + 0x30);
18: lVar3 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
19: switch(*(undefined4 *)(param_1 + 0x3c)) {
20: case 6:
21: while (param_5 = param_5 + -1, -1 < param_5) {
22: ppbVar5 = param_2 + 1;
23: uVar6 = (ulong)param_4;
24: param_4 = param_4 + 1;
25: pbVar8 = *param_2;
26: param_2 = ppbVar5;
27: if (iVar2 != 0) {
28: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
29: pbVar7 = pbVar8;
30: do {
31: pbVar9 = pbVar7 + 3;
32: *puVar4 = (char)((ulong)(*(long *)(lVar3 + (ulong)*pbVar7 * 8) +
33: *(long *)(lVar3 + 0x800 + (ulong)pbVar7[1] * 8) +
34: *(long *)(lVar3 + 0x1000 + (ulong)pbVar7[2] * 8)) >> 0x10);
35: puVar4 = puVar4 + 1;
36: pbVar7 = pbVar9;
37: } while (pbVar9 != pbVar8 + (ulong)(iVar2 - 1) * 3 + 3);
38: }
39: }
40: break;
41: case 7:
42: case 0xc:
43: while (param_5 = param_5 + -1, -1 < param_5) {
44: ppbVar5 = param_2 + 1;
45: uVar6 = (ulong)param_4;
46: param_4 = param_4 + 1;
47: pbVar8 = *param_2;
48: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
49: param_2 = ppbVar5;
50: if (iVar2 != 0) {
51: puVar10 = puVar4;
52: do {
53: bVar1 = *pbVar8;
54: pbVar7 = pbVar8 + 1;
55: puVar11 = puVar10 + 1;
56: pbVar9 = pbVar8 + 2;
57: pbVar8 = pbVar8 + 4;
58: *puVar10 = (char)((ulong)(*(long *)(lVar3 + (ulong)bVar1 * 8) +
59: *(long *)(lVar3 + 0x800 + (ulong)*pbVar7 * 8) +
60: *(long *)(lVar3 + 0x1000 + (ulong)*pbVar9 * 8)) >> 0x10);
61: puVar10 = puVar11;
62: } while (puVar4 + (ulong)(iVar2 - 1) + 1 != puVar11);
63: }
64: }
65: break;
66: case 8:
67: while (param_5 = param_5 + -1, -1 < param_5) {
68: ppbVar5 = param_2 + 1;
69: uVar6 = (ulong)param_4;
70: param_4 = param_4 + 1;
71: pbVar8 = *param_2;
72: param_2 = ppbVar5;
73: if (iVar2 != 0) {
74: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
75: pbVar7 = pbVar8;
76: do {
77: pbVar9 = pbVar7 + 3;
78: *puVar4 = (char)((ulong)(*(long *)(lVar3 + (ulong)pbVar7[2] * 8) +
79: *(long *)(lVar3 + 0x800 + (ulong)pbVar7[1] * 8) +
80: *(long *)(lVar3 + 0x1000 + (ulong)*pbVar7 * 8)) >> 0x10);
81: puVar4 = puVar4 + 1;
82: pbVar7 = pbVar9;
83: } while (pbVar9 != pbVar8 + (ulong)(iVar2 - 1) * 3 + 3);
84: }
85: }
86: break;
87: case 9:
88: case 0xd:
89: while (param_5 = param_5 + -1, -1 < param_5) {
90: ppbVar5 = param_2 + 1;
91: uVar6 = (ulong)param_4;
92: param_4 = param_4 + 1;
93: pbVar8 = *param_2;
94: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
95: param_2 = ppbVar5;
96: if (iVar2 != 0) {
97: puVar10 = puVar4;
98: do {
99: pbVar7 = pbVar8 + 2;
100: pbVar9 = pbVar8 + 1;
101: puVar11 = puVar10 + 1;
102: bVar1 = *pbVar8;
103: pbVar8 = pbVar8 + 4;
104: *puVar10 = (char)((ulong)(*(long *)(lVar3 + (ulong)*pbVar7 * 8) +
105: *(long *)(lVar3 + 0x800 + (ulong)*pbVar9 * 8) +
106: *(long *)(lVar3 + 0x1000 + (ulong)bVar1 * 8)) >> 0x10);
107: puVar10 = puVar11;
108: } while (puVar4 + (ulong)(iVar2 - 1) + 1 != puVar11);
109: }
110: }
111: break;
112: case 10:
113: case 0xe:
114: while (param_5 = param_5 + -1, ppbVar5 = param_2, -1 < param_5) {
115: while( true ) {
116: param_2 = ppbVar5 + 1;
117: uVar6 = (ulong)param_4;
118: param_4 = param_4 + 1;
119: pbVar8 = *ppbVar5;
120: if (iVar2 == 0) break;
121: pbVar7 = pbVar8 + 1;
122: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
123: do {
124: pbVar9 = pbVar7 + 4;
125: *puVar4 = (char)((ulong)(*(long *)(lVar3 + (ulong)pbVar7[2] * 8) +
126: *(long *)(lVar3 + 0x800 + (ulong)pbVar7[1] * 8) +
127: *(long *)(lVar3 + 0x1000 + (ulong)*pbVar7 * 8)) >> 0x10);
128: pbVar7 = pbVar9;
129: puVar4 = puVar4 + 1;
130: } while (pbVar8 + (ulong)(iVar2 - 1) * 4 + 5 != pbVar9);
131: param_5 = param_5 + -1;
132: ppbVar5 = param_2;
133: if (param_5 < 0) {
134: return;
135: }
136: }
137: }
138: break;
139: case 0xb:
140: case 0xf:
141: while (param_5 = param_5 + -1, -1 < param_5) {
142: ppbVar5 = param_2 + 1;
143: uVar6 = (ulong)param_4;
144: param_4 = param_4 + 1;
145: pbVar8 = *param_2;
146: param_2 = ppbVar5;
147: if (iVar2 != 0) {
148: pbVar7 = pbVar8 + 1;
149: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
150: do {
151: pbVar9 = pbVar7 + 4;
152: *puVar4 = (char)((ulong)(*(long *)(lVar3 + (ulong)*pbVar7 * 8) +
153: *(long *)(lVar3 + 0x800 + (ulong)pbVar7[1] * 8) +
154: *(long *)(lVar3 + 0x1000 + (ulong)pbVar7[2] * 8)) >> 0x10);
155: pbVar7 = pbVar9;
156: puVar4 = puVar4 + 1;
157: } while (pbVar8 + (ulong)(iVar2 - 1) * 4 + 5 != pbVar9);
158: }
159: }
160: break;
161: default:
162: while (param_5 = param_5 + -1, -1 < param_5) {
163: ppbVar5 = param_2 + 1;
164: uVar6 = (ulong)param_4;
165: param_4 = param_4 + 1;
166: pbVar8 = *param_2;
167: param_2 = ppbVar5;
168: if (iVar2 != 0) {
169: puVar4 = *(undefined **)(*param_3 + uVar6 * 8);
170: pbVar7 = pbVar8;
171: do {
172: pbVar9 = pbVar7 + 3;
173: *puVar4 = (char)((ulong)(*(long *)(lVar3 + (ulong)*pbVar7 * 8) +
174: *(long *)(lVar3 + 0x800 + (ulong)pbVar7[1] * 8) +
175: *(long *)(lVar3 + 0x1000 + (ulong)pbVar7[2] * 8)) >> 0x10);
176: puVar4 = puVar4 + 1;
177: pbVar7 = pbVar9;
178: } while (pbVar9 != pbVar8 + (ulong)(iVar2 - 1) * 3 + 3);
179: }
180: }
181: }
182: return;
183: }
184: 
