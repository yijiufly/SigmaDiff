1: 
2: void FUN_00120710(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
3: 
4: {
5: undefined uVar1;
6: byte bVar2;
7: uint uVar3;
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
18: long lVar14;
19: undefined *puVar15;
20: ulong uVar16;
21: undefined8 *puStack72;
22: uint uStack64;
23: int iStack60;
24: 
25: uStack64 = param_3;
26: iStack60 = param_5;
27: if (*(int *)(param_1 + 0x40) - 6U < 10) {
28: uVar3 = *(uint *)(param_1 + 0x88);
29: lVar4 = *(long *)(param_1 + 0x268);
30: lVar5 = *(long *)(param_1 + 0x1a8);
31: lVar6 = *(long *)(lVar4 + 0x10);
32: lVar7 = *(long *)(lVar4 + 0x18);
33: lVar8 = *(long *)(lVar4 + 0x20);
34: lVar4 = *(long *)(lVar4 + 0x28);
35: puStack72 = param_4;
36: switch(*(int *)(param_1 + 0x40)) {
37: case 6:
38: while (iStack60 = iStack60 + -1, -1 < iStack60) {
39: uVar13 = (ulong)uStack64;
40: puVar12 = puStack72 + 1;
41: uStack64 = uStack64 + 1;
42: lVar9 = *(long *)(*param_2 + uVar13 * 8);
43: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
44: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
45: puVar15 = (undefined *)*puStack72;
46: lVar14 = 0;
47: puStack72 = puVar12;
48: if (uVar3 != 0) {
49: do {
50: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
51: bVar2 = *(byte *)(lVar9 + lVar14);
52: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
53: lVar14 = lVar14 + 1;
54: *puVar15 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
55: puVar15[1] = *(undefined *)
56: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
57: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
58: (uint)bVar2));
59: puVar15[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
60: puVar15 = puVar15 + 3;
61: } while ((uint)lVar14 < uVar3);
62: }
63: }
64: break;
65: default:
66: while (iStack60 = iStack60 + -1, -1 < iStack60) {
67: uVar13 = (ulong)uStack64;
68: puVar12 = puStack72 + 1;
69: uStack64 = uStack64 + 1;
70: lVar9 = *(long *)(*param_2 + uVar13 * 8);
71: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
72: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
73: puVar15 = (undefined *)*puStack72;
74: lVar14 = 0;
75: puStack72 = puVar12;
76: if (uVar3 != 0) {
77: do {
78: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
79: bVar2 = *(byte *)(lVar9 + lVar14);
80: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
81: lVar14 = lVar14 + 1;
82: *puVar15 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
83: puVar15[1] = *(undefined *)
84: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
85: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
86: (uint)bVar2));
87: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
88: puVar15[3] = 0xff;
89: puVar15[2] = uVar1;
90: puVar15 = puVar15 + 4;
91: } while ((uint)lVar14 < uVar3);
92: }
93: }
94: break;
95: case 8:
96: while (iStack60 = iStack60 + -1, -1 < iStack60) {
97: uVar13 = (ulong)uStack64;
98: puVar12 = puStack72 + 1;
99: uStack64 = uStack64 + 1;
100: lVar9 = *(long *)(*param_2 + uVar13 * 8);
101: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
102: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
103: puVar15 = (undefined *)*puStack72;
104: lVar14 = 0;
105: puStack72 = puVar12;
106: if (uVar3 != 0) {
107: do {
108: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
109: bVar2 = *(byte *)(lVar9 + lVar14);
110: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
111: lVar14 = lVar14 + 1;
112: puVar15[2] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
113: puVar15[1] = *(undefined *)
114: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
115: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
116: (uint)bVar2));
117: *puVar15 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
118: puVar15 = puVar15 + 3;
119: } while ((uint)lVar14 < uVar3);
120: }
121: }
122: break;
123: case 9:
124: case 0xd:
125: while (iStack60 = iStack60 + -1, -1 < iStack60) {
126: uVar13 = (ulong)uStack64;
127: puVar12 = puStack72 + 1;
128: uStack64 = uStack64 + 1;
129: lVar9 = *(long *)(*param_2 + uVar13 * 8);
130: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
131: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
132: lVar14 = 0;
133: puVar15 = (undefined *)*puStack72;
134: puStack72 = puVar12;
135: if (uVar3 != 0) {
136: do {
137: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
138: bVar2 = *(byte *)(lVar9 + lVar14);
139: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
140: lVar14 = lVar14 + 1;
141: puVar15[2] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
142: puVar15[1] = *(undefined *)
143: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
144: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
145: (uint)bVar2));
146: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
147: puVar15[3] = 0xff;
148: *puVar15 = uVar1;
149: puVar15 = puVar15 + 4;
150: } while ((uint)lVar14 < uVar3);
151: }
152: }
153: break;
154: case 10:
155: case 0xe:
156: while (iStack60 = iStack60 + -1, -1 < iStack60) {
157: uVar13 = (ulong)uStack64;
158: puVar12 = puStack72 + 1;
159: uStack64 = uStack64 + 1;
160: lVar9 = *(long *)(*param_2 + uVar13 * 8);
161: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
162: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
163: puVar15 = (undefined *)*puStack72;
164: lVar14 = 0;
165: puStack72 = puVar12;
166: if (uVar3 != 0) {
167: do {
168: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
169: bVar2 = *(byte *)(lVar9 + lVar14);
170: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
171: lVar14 = lVar14 + 1;
172: puVar15[3] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
173: puVar15[2] = *(undefined *)
174: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
175: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
176: (uint)bVar2));
177: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
178: *puVar15 = 0xff;
179: puVar15[1] = uVar1;
180: puVar15 = puVar15 + 4;
181: } while ((uint)lVar14 < uVar3);
182: }
183: }
184: break;
185: case 0xb:
186: case 0xf:
187: while (iStack60 = iStack60 + -1, -1 < iStack60) {
188: while( true ) {
189: uVar13 = (ulong)uStack64;
190: puVar12 = puStack72 + 1;
191: uStack64 = uStack64 + 1;
192: lVar9 = *(long *)(*param_2 + uVar13 * 8);
193: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
194: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
195: puVar15 = (undefined *)*puStack72;
196: lVar14 = 0;
197: puStack72 = puVar12;
198: if (uVar3 == 0) break;
199: do {
200: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
201: bVar2 = *(byte *)(lVar9 + lVar14);
202: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
203: lVar14 = lVar14 + 1;
204: puVar15[1] = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
205: puVar15[2] = *(undefined *)
206: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
207: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
208: (uint)bVar2));
209: uVar1 = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
210: *puVar15 = 0xff;
211: puVar15[3] = uVar1;
212: puVar15 = puVar15 + 4;
213: } while ((uint)lVar14 < uVar3);
214: iStack60 = iStack60 + -1;
215: if (iStack60 < 0) {
216: return;
217: }
218: }
219: }
220: }
221: }
222: else {
223: lVar4 = *(long *)(param_1 + 0x268);
224: uVar3 = *(uint *)(param_1 + 0x88);
225: lVar5 = *(long *)(param_1 + 0x1a8);
226: lVar6 = *(long *)(lVar4 + 0x10);
227: lVar7 = *(long *)(lVar4 + 0x18);
228: lVar8 = *(long *)(lVar4 + 0x20);
229: lVar4 = *(long *)(lVar4 + 0x28);
230: puStack72 = param_4;
231: while (iStack60 = iStack60 + -1, -1 < iStack60) {
232: uVar13 = (ulong)uStack64;
233: puVar12 = puStack72 + 1;
234: uStack64 = uStack64 + 1;
235: lVar9 = *(long *)(*param_2 + uVar13 * 8);
236: lVar10 = *(long *)(param_2[1] + uVar13 * 8);
237: lVar11 = *(long *)(param_2[2] + uVar13 * 8);
238: puVar15 = (undefined *)*puStack72;
239: lVar14 = 0;
240: puStack72 = puVar12;
241: if (uVar3 != 0) {
242: do {
243: uVar16 = (ulong)*(byte *)(lVar11 + lVar14);
244: bVar2 = *(byte *)(lVar9 + lVar14);
245: uVar13 = (ulong)*(byte *)(lVar10 + lVar14);
246: lVar14 = lVar14 + 1;
247: *puVar15 = *(undefined *)(lVar5 + (int)(*(int *)(lVar6 + uVar16 * 4) + (uint)bVar2));
248: puVar15[1] = *(undefined *)
249: (lVar5 + (int)((int)((ulong)(*(long *)(lVar4 + uVar13 * 8) +
250: *(long *)(lVar8 + uVar16 * 8)) >> 0x10) +
251: (uint)bVar2));
252: puVar15[2] = *(undefined *)(lVar5 + (int)((uint)bVar2 + *(int *)(lVar7 + uVar13 * 4)));
253: puVar15 = puVar15 + 3;
254: } while ((uint)lVar14 < uVar3);
255: }
256: }
257: }
258: return;
259: }
260: 
