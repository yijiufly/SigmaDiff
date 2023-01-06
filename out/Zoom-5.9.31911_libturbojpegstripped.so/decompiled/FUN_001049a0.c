1: 
2: void FUN_001049a0(long param_1,byte **param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: uint uVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: ulong uVar9;
14: byte **ppbVar10;
15: long lVar11;
16: byte *pbVar12;
17: uint uStack56;
18: int iStack52;
19: 
20: uStack56 = param_4;
21: iStack52 = param_5;
22: if (*(int *)(param_1 + 0x3c) - 6U < 10) {
23: uVar4 = *(uint *)(param_1 + 0x30);
24: lVar5 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
25: switch(*(int *)(param_1 + 0x3c)) {
26: case 6:
27: while (iStack52 = iStack52 + -1, -1 < iStack52) {
28: uVar9 = (ulong)uStack56;
29: ppbVar10 = param_2 + 1;
30: uStack56 = uStack56 + 1;
31: pbVar12 = *param_2;
32: lVar6 = *(long *)(*param_3 + uVar9 * 8);
33: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
34: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
35: lVar11 = 0;
36: param_2 = ppbVar10;
37: if (uVar4 != 0) {
38: do {
39: lVar1 = (ulong)*pbVar12 * 8;
40: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
41: lVar3 = ((ulong)pbVar12[2] + 0x200) * 8;
42: *(char *)(lVar6 + lVar11) =
43: (char)((ulong)(*(long *)(lVar5 + (ulong)*pbVar12 * 8) +
44: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
45: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x200) * 8)) >> 0x10);
46: *(char *)(lVar7 + lVar11) =
47: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
48: *(long *)(lVar5 + 0x1800 + lVar2) +
49: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
50: *(char *)(lVar8 + lVar11) =
51: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
52: *(long *)(lVar5 + 0x2800 + lVar2) +
53: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
54: lVar11 = lVar11 + 1;
55: pbVar12 = pbVar12 + 3;
56: } while ((uint)lVar11 < uVar4);
57: }
58: }
59: break;
60: default:
61: while (iStack52 = iStack52 + -1, -1 < iStack52) {
62: uVar9 = (ulong)uStack56;
63: ppbVar10 = param_2 + 1;
64: uStack56 = uStack56 + 1;
65: pbVar12 = *param_2;
66: lVar6 = *(long *)(*param_3 + uVar9 * 8);
67: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
68: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
69: lVar11 = 0;
70: param_2 = ppbVar10;
71: if (uVar4 != 0) {
72: do {
73: lVar1 = (ulong)*pbVar12 * 8;
74: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
75: lVar3 = ((ulong)pbVar12[2] + 0x200) * 8;
76: *(char *)(lVar6 + lVar11) =
77: (char)((ulong)(*(long *)(lVar5 + (ulong)*pbVar12 * 8) +
78: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
79: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x200) * 8)) >> 0x10);
80: *(char *)(lVar7 + lVar11) =
81: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
82: *(long *)(lVar5 + 0x1800 + lVar2) +
83: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
84: *(char *)(lVar8 + lVar11) =
85: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
86: *(long *)(lVar5 + 0x2800 + lVar2) +
87: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
88: lVar11 = lVar11 + 1;
89: pbVar12 = pbVar12 + 4;
90: } while ((uint)lVar11 < uVar4);
91: }
92: }
93: break;
94: case 8:
95: while (iStack52 = iStack52 + -1, -1 < iStack52) {
96: uVar9 = (ulong)uStack56;
97: ppbVar10 = param_2 + 1;
98: uStack56 = uStack56 + 1;
99: pbVar12 = *param_2;
100: lVar6 = *(long *)(*param_3 + uVar9 * 8);
101: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
102: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
103: lVar11 = 0;
104: param_2 = ppbVar10;
105: if (uVar4 != 0) {
106: do {
107: lVar1 = (ulong)pbVar12[2] * 8;
108: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
109: lVar3 = ((ulong)*pbVar12 + 0x200) * 8;
110: *(char *)(lVar6 + lVar11) =
111: (char)((ulong)(*(long *)(lVar5 + (ulong)pbVar12[2] * 8) +
112: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
113: *(long *)(lVar5 + ((ulong)*pbVar12 + 0x200) * 8)) >> 0x10);
114: *(char *)(lVar7 + lVar11) =
115: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
116: *(long *)(lVar5 + 0x1800 + lVar2) +
117: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
118: *(char *)(lVar8 + lVar11) =
119: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
120: *(long *)(lVar5 + 0x2800 + lVar2) +
121: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
122: lVar11 = lVar11 + 1;
123: pbVar12 = pbVar12 + 3;
124: } while ((uint)lVar11 < uVar4);
125: }
126: }
127: break;
128: case 9:
129: case 0xd:
130: while (iStack52 = iStack52 + -1, -1 < iStack52) {
131: uVar9 = (ulong)uStack56;
132: ppbVar10 = param_2 + 1;
133: uStack56 = uStack56 + 1;
134: pbVar12 = *param_2;
135: lVar6 = *(long *)(*param_3 + uVar9 * 8);
136: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
137: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
138: lVar11 = 0;
139: param_2 = ppbVar10;
140: if (uVar4 != 0) {
141: do {
142: lVar1 = (ulong)pbVar12[2] * 8;
143: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
144: lVar3 = ((ulong)*pbVar12 + 0x200) * 8;
145: *(char *)(lVar6 + lVar11) =
146: (char)((ulong)(*(long *)(lVar5 + (ulong)pbVar12[2] * 8) +
147: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
148: *(long *)(lVar5 + ((ulong)*pbVar12 + 0x200) * 8)) >> 0x10);
149: *(char *)(lVar7 + lVar11) =
150: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
151: *(long *)(lVar5 + 0x1800 + lVar2) +
152: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
153: *(char *)(lVar8 + lVar11) =
154: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
155: *(long *)(lVar5 + 0x2800 + lVar2) +
156: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
157: lVar11 = lVar11 + 1;
158: pbVar12 = pbVar12 + 4;
159: } while ((uint)lVar11 < uVar4);
160: }
161: }
162: break;
163: case 10:
164: case 0xe:
165: while (iStack52 = iStack52 + -1, -1 < iStack52) {
166: uVar9 = (ulong)uStack56;
167: ppbVar10 = param_2 + 1;
168: uStack56 = uStack56 + 1;
169: pbVar12 = *param_2;
170: lVar6 = *(long *)(*param_3 + uVar9 * 8);
171: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
172: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
173: lVar11 = 0;
174: param_2 = ppbVar10;
175: if (uVar4 != 0) {
176: do {
177: lVar1 = (ulong)pbVar12[3] * 8;
178: lVar2 = ((ulong)pbVar12[2] + 0x100) * 8;
179: lVar3 = ((ulong)pbVar12[1] + 0x200) * 8;
180: *(char *)(lVar6 + lVar11) =
181: (char)((ulong)(*(long *)(lVar5 + (ulong)pbVar12[3] * 8) +
182: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x100) * 8) +
183: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x200) * 8)) >> 0x10);
184: *(char *)(lVar7 + lVar11) =
185: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
186: *(long *)(lVar5 + 0x1800 + lVar2) +
187: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
188: *(char *)(lVar8 + lVar11) =
189: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
190: *(long *)(lVar5 + 0x2800 + lVar2) +
191: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
192: lVar11 = lVar11 + 1;
193: pbVar12 = pbVar12 + 4;
194: } while ((uint)lVar11 < uVar4);
195: }
196: }
197: break;
198: case 0xb:
199: case 0xf:
200: while (iStack52 = iStack52 + -1, ppbVar10 = param_2, -1 < iStack52) {
201: while( true ) {
202: uVar9 = (ulong)uStack56;
203: param_2 = ppbVar10 + 1;
204: uStack56 = uStack56 + 1;
205: pbVar12 = *ppbVar10;
206: lVar6 = *(long *)(*param_3 + uVar9 * 8);
207: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
208: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
209: lVar11 = 0;
210: if (uVar4 == 0) break;
211: do {
212: lVar1 = (ulong)pbVar12[1] * 8;
213: lVar2 = ((ulong)pbVar12[2] + 0x100) * 8;
214: lVar3 = ((ulong)pbVar12[3] + 0x200) * 8;
215: *(char *)(lVar6 + lVar11) =
216: (char)((ulong)(*(long *)(lVar5 + (ulong)pbVar12[1] * 8) +
217: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x100) * 8) +
218: *(long *)(lVar5 + ((ulong)pbVar12[3] + 0x200) * 8)) >> 0x10);
219: *(char *)(lVar7 + lVar11) =
220: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) +
221: *(long *)(lVar5 + 0x1800 + lVar2) +
222: *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
223: *(char *)(lVar8 + lVar11) =
224: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) +
225: *(long *)(lVar5 + 0x2800 + lVar2) +
226: *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
227: lVar11 = lVar11 + 1;
228: pbVar12 = pbVar12 + 4;
229: } while ((uint)lVar11 < uVar4);
230: iStack52 = iStack52 + -1;
231: ppbVar10 = param_2;
232: if (iStack52 < 0) {
233: return;
234: }
235: }
236: }
237: }
238: }
239: else {
240: uVar4 = *(uint *)(param_1 + 0x30);
241: lVar5 = *(long *)(*(long *)(param_1 + 0x1d8) + 0x10);
242: while (iStack52 = iStack52 + -1, -1 < iStack52) {
243: uVar9 = (ulong)uStack56;
244: ppbVar10 = param_2 + 1;
245: uStack56 = uStack56 + 1;
246: pbVar12 = *param_2;
247: lVar6 = *(long *)(*param_3 + uVar9 * 8);
248: lVar7 = *(long *)(param_3[1] + uVar9 * 8);
249: lVar8 = *(long *)(param_3[2] + uVar9 * 8);
250: lVar11 = 0;
251: param_2 = ppbVar10;
252: if (uVar4 != 0) {
253: do {
254: lVar1 = (ulong)*pbVar12 * 8;
255: lVar2 = ((ulong)pbVar12[1] + 0x100) * 8;
256: lVar3 = ((ulong)pbVar12[2] + 0x200) * 8;
257: *(char *)(lVar6 + lVar11) =
258: (char)((ulong)(*(long *)(lVar5 + (ulong)*pbVar12 * 8) +
259: *(long *)(lVar5 + ((ulong)pbVar12[1] + 0x100) * 8) +
260: *(long *)(lVar5 + ((ulong)pbVar12[2] + 0x200) * 8)) >> 0x10);
261: *(char *)(lVar7 + lVar11) =
262: (char)((ulong)(*(long *)(lVar5 + 0x1800 + lVar1) + *(long *)(lVar5 + 0x1800 + lVar2)
263: + *(long *)(lVar5 + 0x1800 + lVar3)) >> 0x10);
264: *(char *)(lVar8 + lVar11) =
265: (char)((ulong)(*(long *)(lVar5 + 0x2800 + lVar1) + *(long *)(lVar5 + 0x2800 + lVar2)
266: + *(long *)(lVar5 + 0x2800 + lVar3)) >> 0x10);
267: lVar11 = lVar11 + 1;
268: pbVar12 = pbVar12 + 3;
269: } while ((uint)lVar11 < uVar4);
270: }
271: }
272: }
273: return;
274: }
275: 
