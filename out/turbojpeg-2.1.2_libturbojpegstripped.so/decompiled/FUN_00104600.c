1: 
2: void FUN_00104600(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: int iVar4;
9: long lVar5;
10: byte *pbVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: ulong uVar10;
15: byte **ppbVar11;
16: byte *pbVar12;
17: byte *pbVar13;
18: long lVar14;
19: uint uStack68;
20: int iStack60;
21: 
22: iVar4 = *(int *)(param_1 + 0x30);
23: lVar5 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
24: uStack68 = param_4;
25: iStack60 = param_5;
26: switch(*(undefined4 *)(param_1 + 0x3c)) {
27: case 6:
28: while (iStack60 = iStack60 + -1, -1 < iStack60) {
29: uVar10 = (ulong)uStack68;
30: ppbVar11 = param_2 + 1;
31: pbVar6 = *param_2;
32: lVar7 = *(long *)(*param_3 + uVar10 * 8);
33: uStack68 = uStack68 + 1;
34: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
35: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
36: param_2 = ppbVar11;
37: if (iVar4 != 0) {
38: lVar14 = 0;
39: pbVar12 = pbVar6;
40: do {
41: pbVar13 = pbVar12 + 3;
42: lVar1 = (ulong)*pbVar12 * 8;
43: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
44: lVar3 = ((ulong)pbVar12[2] + 0x200) * 8;
45: *(char *)(lVar7 + lVar14) =
46: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
47: *(long *)(lVar5 + (ulong)*pbVar12 * 8) +
48: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x200) * 8)) >> 0x10);
49: *(char *)(lVar8 + lVar14) =
50: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
51: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
52: *(char *)(lVar9 + lVar14) =
53: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
54: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
55: lVar14 = lVar14 + 1;
56: pbVar12 = pbVar13;
57: } while (pbVar13 != pbVar6 + (ulong)(iVar4 - 1) * 3 + 3);
58: }
59: }
60: break;
61: case 7:
62: case 0xc:
63: while (iStack60 = iStack60 + -1, -1 < iStack60) {
64: uVar10 = (ulong)uStack68;
65: ppbVar11 = param_2 + 1;
66: pbVar6 = *param_2;
67: lVar7 = *(long *)(*param_3 + uVar10 * 8);
68: uStack68 = uStack68 + 1;
69: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
70: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
71: param_2 = ppbVar11;
72: if (iVar4 != 0) {
73: lVar14 = 0;
74: do {
75: lVar1 = (ulong)pbVar6[lVar14 * 4] * 8;
76: lVar2 = ((ulong)pbVar6[lVar14 * 4 + 1] + 0x100) * 8;
77: lVar3 = ((ulong)pbVar6[lVar14 * 4 + 2] + 0x200) * 8;
78: *(char *)(lVar7 + lVar14) =
79: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 1] + 0x100) * 8) +
80: *(long *)(lVar5 + (ulong)pbVar6[lVar14 * 4] * 8) +
81: *(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 2] + 0x200) * 8)) >> 0x10
82: );
83: *(char *)(lVar8 + lVar14) =
84: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
85: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
86: *(char *)(lVar9 + lVar14) =
87: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
88: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
89: lVar14 = lVar14 + 1;
90: } while ((ulong)(iVar4 - 1) + 1 != lVar14);
91: }
92: }
93: break;
94: case 8:
95: while (iStack60 = iStack60 + -1, -1 < iStack60) {
96: uVar10 = (ulong)uStack68;
97: ppbVar11 = param_2 + 1;
98: pbVar6 = *param_2;
99: lVar7 = *(long *)(*param_3 + uVar10 * 8);
100: uStack68 = uStack68 + 1;
101: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
102: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
103: param_2 = ppbVar11;
104: if (iVar4 != 0) {
105: lVar14 = 0;
106: pbVar12 = pbVar6;
107: do {
108: pbVar13 = pbVar12 + 3;
109: lVar1 = (ulong)pbVar12[2] * 8;
110: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
111: lVar3 = ((ulong)*pbVar12 + 0x200) * 8;
112: *(char *)(lVar7 + lVar14) =
113: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
114: *(long *)(lVar5 + (ulong)pbVar12[2] * 8) +
115: *(long *)(lVar5 + ((ulong)*pbVar12 + 0x200) * 8)) >> 0x10);
116: *(char *)(lVar8 + lVar14) =
117: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
118: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
119: *(char *)(lVar9 + lVar14) =
120: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
121: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
122: lVar14 = lVar14 + 1;
123: pbVar12 = pbVar13;
124: } while (pbVar13 != pbVar6 + (ulong)(iVar4 - 1) * 3 + 3);
125: }
126: }
127: break;
128: case 9:
129: case 0xd:
130: while (iStack60 = iStack60 + -1, -1 < iStack60) {
131: uVar10 = (ulong)uStack68;
132: ppbVar11 = param_2 + 1;
133: pbVar6 = *param_2;
134: lVar7 = *(long *)(*param_3 + uVar10 * 8);
135: uStack68 = uStack68 + 1;
136: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
137: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
138: param_2 = ppbVar11;
139: if (iVar4 != 0) {
140: lVar14 = 0;
141: do {
142: lVar1 = (ulong)pbVar6[lVar14 * 4 + 2] * 8;
143: lVar2 = ((ulong)pbVar6[lVar14 * 4 + 1] + 0x100) * 8;
144: lVar3 = ((ulong)pbVar6[lVar14 * 4] + 0x200) * 8;
145: *(char *)(lVar7 + lVar14) =
146: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 1] + 0x100) * 8) +
147: *(long *)(lVar5 + (ulong)pbVar6[lVar14 * 4 + 2] * 8) +
148: *(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4] + 0x200) * 8)) >> 0x10);
149: *(char *)(lVar8 + lVar14) =
150: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
151: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
152: *(char *)(lVar9 + lVar14) =
153: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
154: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
155: lVar14 = lVar14 + 1;
156: } while ((ulong)(iVar4 - 1) + 1 != lVar14);
157: }
158: }
159: break;
160: case 10:
161: case 0xe:
162: while (param_5 = param_5 + -1, -1 < param_5) {
163: uVar10 = (ulong)param_4;
164: ppbVar11 = param_2 + 1;
165: pbVar6 = *param_2;
166: lVar7 = *(long *)(*param_3 + uVar10 * 8);
167: param_4 = param_4 + 1;
168: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
169: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
170: param_2 = ppbVar11;
171: if (iVar4 != 0) {
172: lVar14 = 0;
173: do {
174: lVar1 = (ulong)pbVar6[lVar14 * 4 + 3] * 8;
175: lVar2 = ((ulong)pbVar6[lVar14 * 4 + 2] + 0x100) * 8;
176: lVar3 = ((ulong)pbVar6[lVar14 * 4 + 1] + 0x200) * 8;
177: *(char *)(lVar7 + lVar14) =
178: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 2] + 0x100) * 8) +
179: *(long *)(lVar5 + (ulong)pbVar6[lVar14 * 4 + 3] * 8) +
180: *(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 1] + 0x200) * 8)) >> 0x10
181: );
182: *(char *)(lVar8 + lVar14) =
183: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
184: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
185: *(char *)(lVar9 + lVar14) =
186: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
187: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
188: lVar14 = lVar14 + 1;
189: } while ((ulong)(iVar4 - 1) + 1 != lVar14);
190: }
191: }
192: break;
193: case 0xb:
194: case 0xf:
195: while (iStack60 = iStack60 + -1, -1 < iStack60) {
196: uVar10 = (ulong)uStack68;
197: ppbVar11 = param_2 + 1;
198: pbVar6 = *param_2;
199: lVar7 = *(long *)(*param_3 + uVar10 * 8);
200: uStack68 = uStack68 + 1;
201: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
202: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
203: param_2 = ppbVar11;
204: if (iVar4 != 0) {
205: lVar14 = 0;
206: do {
207: lVar1 = (ulong)pbVar6[lVar14 * 4 + 1] * 8;
208: lVar2 = ((ulong)pbVar6[lVar14 * 4 + 2] + 0x100) * 8;
209: lVar3 = ((ulong)pbVar6[lVar14 * 4 + 3] + 0x200) * 8;
210: *(char *)(lVar7 + lVar14) =
211: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 2] + 0x100) * 8) +
212: *(long *)(lVar5 + (ulong)pbVar6[lVar14 * 4 + 1] * 8) +
213: *(long *)(lVar5 + ((ulong)pbVar6[lVar14 * 4 + 3] + 0x200) * 8)) >> 0x10
214: );
215: *(char *)(lVar8 + lVar14) =
216: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
217: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
218: *(char *)(lVar9 + lVar14) =
219: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
220: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
221: lVar14 = lVar14 + 1;
222: } while ((ulong)(iVar4 - 1) + 1 != lVar14);
223: }
224: }
225: break;
226: default:
227: while (iStack60 = iStack60 + -1, -1 < iStack60) {
228: uVar10 = (ulong)uStack68;
229: ppbVar11 = param_2 + 1;
230: pbVar6 = *param_2;
231: lVar7 = *(long *)(*param_3 + uVar10 * 8);
232: uStack68 = uStack68 + 1;
233: lVar8 = *(long *)(param_3[1] + uVar10 * 8);
234: lVar9 = *(long *)(param_3[2] + uVar10 * 8);
235: param_2 = ppbVar11;
236: if (iVar4 != 0) {
237: lVar14 = 0;
238: pbVar12 = pbVar6;
239: do {
240: pbVar13 = pbVar12 + 3;
241: lVar1 = (ulong)*pbVar12 * 8;
242: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
243: lVar3 = ((ulong)pbVar12[2] + 0x200) * 8;
244: *(char *)(lVar7 + lVar14) =
245: (char)((ulong)(*(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
246: *(long *)(lVar5 + (ulong)*pbVar12 * 8) +
247: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x200) * 8)) >> 0x10);
248: *(char *)(lVar8 + lVar14) =
249: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar2) + *(long *)(lVar5 + 0x1800 + lVar1)
250: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
251: *(char *)(lVar9 + lVar14) =
252: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar2) + *(long *)(lVar5 + 0x2800 + lVar1)
253: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
254: lVar14 = lVar14 + 1;
255: pbVar12 = pbVar13;
256: } while (pbVar6 + (ulong)(iVar4 - 1) * 3 + 3 != pbVar13);
257: }
258: }
259: }
260: return;
261: }
262: 
