1: 
2: void FUN_0012a210(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
3: 
4: {
5: undefined uVar1;
6: byte bVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: undefined8 *puVar12;
17: ulong uVar13;
18: undefined *puVar14;
19: undefined *puVar15;
20: undefined *puVar16;
21: long lVar17;
22: ulong uVar18;
23: undefined8 *puStack88;
24: uint uStack76;
25: int iStack68;
26: 
27: iVar3 = *(int *)(param_1 + 0x88);
28: lVar4 = *(long *)(param_1 + 0x268);
29: lVar5 = *(long *)(param_1 + 0x1a8);
30: lVar6 = *(long *)(lVar4 + 0x10);
31: lVar7 = *(long *)(lVar4 + 0x18);
32: lVar8 = *(long *)(lVar4 + 0x20);
33: lVar4 = *(long *)(lVar4 + 0x28);
34: uStack76 = param_3;
35: iStack68 = param_5;
36: switch(*(undefined4 *)(param_1 + 0x40)) {
37: case 6:
38: puStack88 = param_4;
39: while (iStack68 = iStack68 + -1, -1 < iStack68) {
40: uVar13 = (ulong)uStack76;
41: puVar12 = puStack88 + 1;
42: lVar9 = *(long *)(*param_2 + uVar13 * 8);
43: uStack76 = uStack76 + 1;
44: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
45: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
46: puVar15 = (undefined *)*puStack88;
47: puStack88 = puVar12;
48: if (iVar3 != 0) {
49: lVar17 = 0;
50: puVar14 = puVar15;
51: do {
52: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
53: bVar2 = *(byte *)(lVar9 + lVar17);
54: puVar16 = puVar14 + 3;
55: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
56: lVar17 = lVar17 + 1;
57: *puVar14 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
58: puVar14[1] = *(undefined *)
59: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
60: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
61: (uint)bVar2));
62: puVar14[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
63: puVar14 = puVar16;
64: } while (puVar16 != puVar15 + (ulong)(iVar3 - 1) * 3 + 3);
65: }
66: }
67: break;
68: case 7:
69: case 0xc:
70: puStack88 = param_4;
71: while (iStack68 = iStack68 + -1, -1 < iStack68) {
72: uVar13 = (ulong)uStack76;
73: puVar12 = puStack88 + 1;
74: lVar9 = *(long *)(*param_2 + uVar13 * 8);
75: uStack76 = uStack76 + 1;
76: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
77: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
78: puVar15 = (undefined *)*puStack88;
79: puStack88 = puVar12;
80: if (iVar3 != 0) {
81: lVar17 = 0;
82: do {
83: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
84: bVar2 = *(byte *)(lVar9 + lVar17);
85: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
86: lVar17 = lVar17 + 1;
87: *puVar15 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
88: puVar15[1] = *(undefined *)
89: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
90: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
91: (uint)bVar2));
92: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
93: puVar15[3] = 0xff;
94: puVar15[2] = uVar1;
95: puVar15 = puVar15 + 4;
96: } while (lVar17 != (ulong)(iVar3 - 1) + 1);
97: }
98: }
99: break;
100: case 8:
101: puStack88 = param_4;
102: while (iStack68 = iStack68 + -1, -1 < iStack68) {
103: uVar13 = (ulong)uStack76;
104: puVar12 = puStack88 + 1;
105: lVar9 = *(long *)(*param_2 + uVar13 * 8);
106: uStack76 = uStack76 + 1;
107: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
108: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
109: puVar15 = (undefined *)*puStack88;
110: puStack88 = puVar12;
111: if (iVar3 != 0) {
112: lVar17 = 0;
113: puVar14 = puVar15;
114: do {
115: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
116: bVar2 = *(byte *)(lVar9 + lVar17);
117: puVar16 = puVar14 + 3;
118: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
119: lVar17 = lVar17 + 1;
120: puVar14[2] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
121: puVar14[1] = *(undefined *)
122: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
123: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
124: (uint)bVar2));
125: *puVar14 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
126: puVar14 = puVar16;
127: } while (puVar16 != puVar15 + (ulong)(iVar3 - 1) * 3 + 3);
128: }
129: }
130: break;
131: case 9:
132: case 0xd:
133: puStack88 = param_4;
134: while (iStack68 = iStack68 + -1, -1 < iStack68) {
135: uVar13 = (ulong)uStack76;
136: puVar12 = puStack88 + 1;
137: lVar9 = *(long *)(*param_2 + uVar13 * 8);
138: uStack76 = uStack76 + 1;
139: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
140: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
141: puVar15 = (undefined *)*puStack88;
142: puStack88 = puVar12;
143: if (iVar3 != 0) {
144: lVar17 = 0;
145: do {
146: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
147: bVar2 = *(byte *)(lVar9 + lVar17);
148: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
149: lVar17 = lVar17 + 1;
150: puVar15[2] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
151: puVar15[1] = *(undefined *)
152: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
153: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
154: (uint)bVar2));
155: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
156: puVar15[3] = 0xff;
157: *puVar15 = uVar1;
158: puVar15 = puVar15 + 4;
159: } while (lVar17 != (ulong)(iVar3 - 1) + 1);
160: }
161: }
162: break;
163: case 10:
164: case 0xe:
165: while (param_5 = param_5 + -1, -1 < param_5) {
166: uVar13 = (ulong)param_3;
167: puVar12 = param_4 + 1;
168: lVar9 = *(long *)(*param_2 + uVar13 * 8);
169: param_3 = param_3 + 1;
170: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
171: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
172: puVar15 = (undefined *)*param_4;
173: param_4 = puVar12;
174: if (iVar3 != 0) {
175: lVar17 = 0;
176: do {
177: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
178: bVar2 = *(byte *)(lVar9 + lVar17);
179: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
180: lVar17 = lVar17 + 1;
181: puVar15[3] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
182: puVar15[2] = *(undefined *)
183: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
184: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
185: (uint)bVar2));
186: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
187: *puVar15 = 0xff;
188: puVar15[1] = uVar1;
189: puVar15 = puVar15 + 4;
190: } while (lVar17 != (ulong)(iVar3 - 1) + 1);
191: }
192: }
193: break;
194: case 0xb:
195: case 0xf:
196: puStack88 = param_4;
197: while (iStack68 = iStack68 + -1, -1 < iStack68) {
198: uVar13 = (ulong)uStack76;
199: puVar12 = puStack88 + 1;
200: lVar9 = *(long *)(*param_2 + uVar13 * 8);
201: uStack76 = uStack76 + 1;
202: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
203: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
204: puVar15 = (undefined *)*puStack88;
205: puStack88 = puVar12;
206: if (iVar3 != 0) {
207: lVar17 = 0;
208: do {
209: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
210: bVar2 = *(byte *)(lVar9 + lVar17);
211: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
212: lVar17 = lVar17 + 1;
213: puVar15[1] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
214: puVar15[2] = *(undefined *)
215: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
216: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
217: (uint)bVar2));
218: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
219: *puVar15 = 0xff;
220: puVar15[3] = uVar1;
221: puVar15 = puVar15 + 4;
222: } while (lVar17 != (ulong)(iVar3 - 1) + 1);
223: }
224: }
225: break;
226: default:
227: puStack88 = param_4;
228: while (iStack68 = iStack68 + -1, -1 < iStack68) {
229: uVar13 = (ulong)uStack76;
230: puVar12 = puStack88 + 1;
231: lVar9 = *(long *)(*param_2 + uVar13 * 8);
232: uStack76 = uStack76 + 1;
233: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
234: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
235: puVar15 = (undefined *)*puStack88;
236: puStack88 = puVar12;
237: if (iVar3 != 0) {
238: lVar17 = 0;
239: puVar14 = puVar15;
240: do {
241: uVar13 = (ulong)*(byte *)(lVar11 + lVar17);
242: bVar2 = *(byte *)(lVar9 + lVar17);
243: puVar16 = puVar14 + 3;
244: uVar18 = (ulong)*(byte *)(lVar10 + lVar17);
245: lVar17 = lVar17 + 1;
246: *puVar14 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar13 * 4) + (uint)bVar2));
247: puVar14[1] = *(undefined *)
248: (lVar5 + (int)((int)((ulong)(*(long *)(lVar8 + uVar13 * 8) +
249: *(long *)(lVar4 + uVar18 * 8)) >> 0x10) +
250: (uint)bVar2));
251: puVar14[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar18 * 4)));
252: puVar14 = puVar16;
253: } while (puVar16 != puVar15 + (ulong)(iVar3 - 1) * 3 + 3);
254: }
255: }
256: }
257: return;
258: }
259: 
