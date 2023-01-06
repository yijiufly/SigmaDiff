1: 
2: undefined8 FUN_00121da0(long param_1,undefined8 *param_2)
3: 
4: {
5: short *psVar1;
6: long *plVar2;
7: byte *pbVar3;
8: undefined4 uVar4;
9: long lVar5;
10: undefined8 uVar6;
11: undefined8 *puVar7;
12: undefined *puVar8;
13: code **ppcVar9;
14: int iVar10;
15: int iVar11;
16: uint uVar12;
17: uint uVar13;
18: int iVar14;
19: int iVar15;
20: int iVar16;
21: long lVar17;
22: byte *pbVar18;
23: ulong uVar19;
24: uint uVar20;
25: uint uVar21;
26: ulong uVar22;
27: ulong uVar23;
28: long in_FS_OFFSET;
29: bool bVar24;
30: ulong uStack328;
31: short *psStack320;
32: ulong uStack312;
33: ulong uStack248;
34: ulong uStack240;
35: short asStack224 [80];
36: long lStack64;
37: 
38: iVar10 = *(int *)(param_1 + 0x118);
39: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
40: lVar17 = (long)*(int *)(param_1 + 0x19c);
41: lVar5 = *(long *)(param_1 + 0x1f0);
42: iVar16 = (*(int *)(param_1 + 0x1a0) - *(int *)(param_1 + 0x19c)) + 1;
43: uVar4 = *(undefined4 *)(param_1 + 0x1a8);
44: uVar6 = (*(undefined8 **)(param_1 + 0x28))[1];
45: *(undefined8 *)(lVar5 + 0x30) = **(undefined8 **)(param_1 + 0x28);
46: *(undefined8 *)(lVar5 + 0x38) = uVar6;
47: if ((iVar10 != 0) && (*(int *)(lVar5 + 0x80) == 0)) {
48: FUN_00120fe0(lVar5,*(undefined4 *)(lVar5 + 0x84));
49: lVar17 = (long)*(int *)(param_1 + 0x19c);
50: }
51: iVar10 = (**(code **)(lVar5 + 0x20))
52: (*param_2,&DAT_0018f100 + lVar17 * 4,iVar16,uVar4,asStack224,&uStack248);
53: pbVar18 = (byte *)((ulong)*(uint *)(lVar5 + 0x70) + *(long *)(lVar5 + 0x78));
54: uStack312 = uStack240;
55: psStack320 = asStack224;
56: if (uStack248 == 0) {
57: bVar24 = false;
58: iVar15 = 0;
59: uVar21 = 0;
60: }
61: else {
62: uStack328 = uStack248;
63: uVar21 = 0;
64: uVar19 = 0;
65: do {
66: iVar15 = 0;
67: uVar22 = uStack328;
68: while ((uVar22 & 1) == 0) {
69: iVar15 = iVar15 + 1;
70: uVar22 = uVar22 >> 1 | 0x8000000000000000;
71: }
72: uVar21 = uVar21 + iVar15;
73: psVar1 = psStack320 + iVar15;
74: uVar22 = uStack312 >> ((byte)iVar15 & 0x3f);
75: if ((psVar1 <= asStack224 + iVar10) && (0xf < (int)uVar21)) {
76: do {
77: FUN_00120910(lVar5);
78: uVar21 = uVar21 - 0x10;
79: if (*(int *)(lVar5 + 0x28) == 0) {
80: lVar17 = *(long *)(lVar5 + 0x88 + (long)*(int *)(lVar5 + 0x68) * 8);
81: FUN_001207a0(lVar5,*(undefined4 *)(lVar17 + 0x3c0),(int)*(char *)(lVar17 + 0x4f0));
82: iVar11 = *(int *)(lVar5 + 0x28);
83: if ((iVar11 == 0) && ((int)uVar19 != 0)) {
84: uVar12 = *(uint *)(lVar5 + 0x48);
85: pbVar3 = pbVar18 + (ulong)((int)uVar19 - 1) + 1;
86: do {
87: if (iVar11 == 0) {
88: uVar13 = uVar12 + 1;
89: uVar19 = (ulong)(*pbVar18 & 1) << (0x18U - (char)uVar13 & 0x3f) |
90: *(ulong *)(lVar5 + 0x40);
91: if (7 < (int)uVar13) {
92: uVar20 = uVar12 - 7 & 7;
93: do {
94: while( true ) {
95: uVar23 = uVar19;
96: puVar8 = *(undefined **)(lVar5 + 0x30);
97: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
98: *puVar8 = (char)(uVar23 >> 0x10);
99: plVar2 = (long *)(lVar5 + 0x38);
100: *plVar2 = *plVar2 + -1;
101: if (*plVar2 == 0) {
102: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
103: iVar11 = (*(code *)puVar7[3])();
104: if (iVar11 == 0) {
105: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
106: *(undefined4 *)(ppcVar9 + 5) = 0x18;
107: (**ppcVar9)();
108: }
109: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
110: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
111: }
112: if (((uint)(uVar23 >> 0x10) & 0xff) == 0xff) break;
113: LAB_00121fb0:
114: uVar13 = uVar13 - 8;
115: uVar19 = uVar23 << 8;
116: if (uVar13 == uVar20) goto LAB_00122050;
117: }
118: puVar8 = *(undefined **)(lVar5 + 0x30);
119: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
120: *puVar8 = 0;
121: plVar2 = (long *)(lVar5 + 0x38);
122: *plVar2 = *plVar2 + -1;
123: if (*plVar2 != 0) goto LAB_00121fb0;
124: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
125: iVar11 = (*(code *)puVar7[3])();
126: if (iVar11 == 0) {
127: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
128: *(undefined4 *)(ppcVar9 + 5) = 0x18;
129: (**ppcVar9)();
130: }
131: uVar13 = uVar13 - 8;
132: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
133: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
134: uVar19 = uVar23 << 8;
135: } while (uVar13 != uVar20);
136: LAB_00122050:
137: uVar19 = uVar23 << 8;
138: uVar13 = uVar12 - 7 & 7;
139: }
140: *(ulong *)(lVar5 + 0x40) = uVar19;
141: *(uint *)(lVar5 + 0x48) = uVar13;
142: uVar12 = uVar13;
143: }
144: pbVar18 = pbVar18 + 1;
145: if (pbVar18 == pbVar3) break;
146: iVar11 = *(int *)(lVar5 + 0x28);
147: } while( true );
148: }
149: }
150: else {
151: plVar2 = (long *)(*(long *)(lVar5 + 0xa8 + (long)*(int *)(lVar5 + 0x68) * 8) + 0x780);
152: *plVar2 = *plVar2 + 1;
153: }
154: uVar19 = 0;
155: pbVar18 = *(byte **)(lVar5 + 0x78);
156: } while (0xf < (int)uVar21);
157: uVar19 = 0;
158: }
159: psStack320 = psVar1 + 1;
160: uStack328 = (uStack328 >> ((byte)iVar15 & 0x3f)) >> 1;
161: uStack312 = uVar22 >> 1;
162: iVar15 = (int)uVar19;
163: if (*psVar1 < 2) {
164: FUN_00120910(lVar5);
165: iVar11 = uVar21 * 0x10 + 1;
166: if (*(int *)(lVar5 + 0x28) == 0) {
167: lVar17 = *(long *)(lVar5 + 0x88 + (long)*(int *)(lVar5 + 0x68) * 8);
168: FUN_001207a0(lVar5,*(undefined4 *)(lVar17 + (long)iVar11 * 4),
169: (int)*(char *)(lVar17 + 0x400 + (long)iVar11));
170: iVar11 = *(int *)(lVar5 + 0x28);
171: if (iVar11 == 0) {
172: uVar21 = *(int *)(lVar5 + 0x48) + 1;
173: uVar12 = *(int *)(lVar5 + 0x48) - 7;
174: uVar13 = uVar12 & 7;
175: uVar19 = (ulong)((uint)uVar22 & 1) << (0x18U - (char)uVar21 & 0x3f) |
176: *(ulong *)(lVar5 + 0x40);
177: if ((int)uVar21 < 8) {
178: *(ulong *)(lVar5 + 0x40) = uVar19;
179: *(uint *)(lVar5 + 0x48) = uVar21;
180: }
181: else {
182: do {
183: while( true ) {
184: uVar22 = uVar19;
185: puVar8 = *(undefined **)(lVar5 + 0x30);
186: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
187: *puVar8 = (char)(uVar22 >> 0x10);
188: plVar2 = (long *)(lVar5 + 0x38);
189: *plVar2 = *plVar2 + -1;
190: if (*plVar2 == 0) {
191: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
192: iVar14 = (*(code *)puVar7[3])();
193: if (iVar14 == 0) {
194: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
195: *(undefined4 *)(ppcVar9 + 5) = 0x18;
196: (**ppcVar9)();
197: }
198: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
199: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
200: }
201: if (((uint)(uVar22 >> 0x10) & 0xff) == 0xff) break;
202: LAB_00122270:
203: uVar21 = uVar21 - 8;
204: uVar19 = uVar22 << 8;
205: if (uVar21 == uVar13) goto LAB_0012230a;
206: }
207: puVar8 = *(undefined **)(lVar5 + 0x30);
208: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
209: *puVar8 = 0;
210: plVar2 = (long *)(lVar5 + 0x38);
211: *plVar2 = *plVar2 + -1;
212: if (*plVar2 != 0) goto LAB_00122270;
213: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
214: iVar14 = (*(code *)puVar7[3])();
215: if (iVar14 == 0) {
216: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
217: *(undefined4 *)(ppcVar9 + 5) = 0x18;
218: (**ppcVar9)();
219: }
220: uVar21 = uVar21 - 8;
221: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
222: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
223: uVar19 = uVar22 << 8;
224: } while (uVar21 != uVar13);
225: LAB_0012230a:
226: *(ulong *)(lVar5 + 0x40) = uVar22 << 8;
227: *(uint *)(lVar5 + 0x48) = uVar12 & 7;
228: if (*(int *)(lVar5 + 0x28) != 0) goto LAB_001221e2;
229: }
230: if (iVar15 != 0) {
231: uVar21 = *(uint *)(lVar5 + 0x48);
232: pbVar3 = pbVar18 + (ulong)(iVar15 - 1) + 1;
233: do {
234: if (iVar11 == 0) {
235: uVar12 = uVar21 + 1;
236: uVar19 = (ulong)(*pbVar18 & 1) << (0x18U - (char)uVar12 & 0x3f) |
237: *(ulong *)(lVar5 + 0x40);
238: if (7 < (int)uVar12) {
239: uVar13 = uVar21 - 7 & 7;
240: do {
241: while( true ) {
242: uVar22 = uVar19;
243: puVar8 = *(undefined **)(lVar5 + 0x30);
244: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
245: *puVar8 = (char)(uVar22 >> 0x10);
246: plVar2 = (long *)(lVar5 + 0x38);
247: *plVar2 = *plVar2 + -1;
248: if (*plVar2 == 0) {
249: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
250: iVar15 = (*(code *)puVar7[3])();
251: if (iVar15 == 0) {
252: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
253: *(undefined4 *)(ppcVar9 + 5) = 0x18;
254: (**ppcVar9)();
255: }
256: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
257: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
258: }
259: if (((uint)(uVar22 >> 0x10) & 0xff) == 0xff) break;
260: LAB_001223a0:
261: uVar12 = uVar12 - 8;
262: uVar19 = uVar22 << 8;
263: if (uVar12 == uVar13) goto LAB_0012243c;
264: }
265: puVar8 = *(undefined **)(lVar5 + 0x30);
266: *(undefined **)(lVar5 + 0x30) = puVar8 + 1;
267: *puVar8 = 0;
268: plVar2 = (long *)(lVar5 + 0x38);
269: *plVar2 = *plVar2 + -1;
270: if (*plVar2 != 0) goto LAB_001223a0;
271: puVar7 = *(undefined8 **)(*(long *)(lVar5 + 0x50) + 0x28);
272: iVar15 = (*(code *)puVar7[3])();
273: if (iVar15 == 0) {
274: ppcVar9 = (code **)**(code ***)(lVar5 + 0x50);
275: *(undefined4 *)(ppcVar9 + 5) = 0x18;
276: (**ppcVar9)();
277: }
278: uVar12 = uVar12 - 8;
279: *(undefined8 *)(lVar5 + 0x30) = *puVar7;
280: *(undefined8 *)(lVar5 + 0x38) = puVar7[1];
281: uVar19 = uVar22 << 8;
282: } while (uVar12 != uVar13);
283: LAB_0012243c:
284: uVar19 = uVar22 << 8;
285: uVar12 = uVar21 - 7 & 7;
286: }
287: uVar21 = uVar12;
288: *(ulong *)(lVar5 + 0x40) = uVar19;
289: *(uint *)(lVar5 + 0x48) = uVar21;
290: }
291: pbVar18 = pbVar18 + 1;
292: if (pbVar18 == pbVar3) break;
293: iVar11 = *(int *)(lVar5 + 0x28);
294: } while( true );
295: }
296: }
297: }
298: else {
299: plVar2 = (long *)(*(long *)(lVar5 + 0xa8 + (long)*(int *)(lVar5 + 0x68) * 8) +
300: (long)iVar11 * 8);
301: *plVar2 = *plVar2 + 1;
302: }
303: LAB_001221e2:
304: pbVar18 = *(byte **)(lVar5 + 0x78);
305: uVar22 = 0;
306: uVar21 = 0;
307: }
308: else {
309: uVar22 = (ulong)(iVar15 + 1);
310: pbVar18[uVar19] = (byte)*psVar1 & 1;
311: }
312: iVar15 = (int)uVar22;
313: uVar19 = uVar22;
314: } while (uStack328 != 0);
315: bVar24 = iVar15 != 0;
316: }
317: if ((0 < (int)(uVar21 | (uint)((long)asStack224 + ((long)iVar16 * 2 - (long)psStack320) >> 1))) ||
318: (bVar24)) {
319: uVar21 = iVar15 + *(int *)(lVar5 + 0x70);
320: iVar16 = *(int *)(lVar5 + 0x6c) + 1;
321: *(int *)(lVar5 + 0x6c) = iVar16;
322: *(uint *)(lVar5 + 0x70) = uVar21;
323: if ((iVar16 == 0x7fff) || (0x3a9 < uVar21)) {
324: FUN_00120910(lVar5);
325: }
326: }
327: puVar7 = *(undefined8 **)(param_1 + 0x28);
328: *puVar7 = *(undefined8 *)(lVar5 + 0x30);
329: puVar7[1] = *(undefined8 *)(lVar5 + 0x38);
330: iVar16 = *(int *)(param_1 + 0x118);
331: if (iVar16 != 0) {
332: iVar10 = *(int *)(lVar5 + 0x80);
333: if (*(int *)(lVar5 + 0x80) == 0) {
334: *(uint *)(lVar5 + 0x84) = *(int *)(lVar5 + 0x84) + 1U & 7;
335: iVar10 = iVar16;
336: }
337: *(int *)(lVar5 + 0x80) = iVar10 + -1;
338: }
339: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
340: /* WARNING: Subroutine does not return */
341: __stack_chk_fail();
342: }
343: return 1;
344: }
345: 
