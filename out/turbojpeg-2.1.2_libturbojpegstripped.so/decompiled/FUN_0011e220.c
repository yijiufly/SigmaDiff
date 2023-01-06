1: 
2: void FUN_0011e220(code **param_1)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: long lVar3;
8: uint uVar4;
9: undefined (*pauVar5) [16];
10: uint uVar6;
11: undefined (*pauVar7) [16];
12: int iVar8;
13: int iVar9;
14: long lVar10;
15: int *piVar11;
16: uint *puVar12;
17: int *piVar13;
18: ulong uVar14;
19: long in_FS_OFFSET;
20: int aiStack2888 [38];
21: undefined *puStack2736;
22: uint uStack2716;
23: ulong uStack2712;
24: int iStack2704;
25: int iStack2700;
26: int *piStack2696;
27: uint uStack2688;
28: uint uStack2684;
29: int aiStack2680 [12];
30: int aiStack2632 [64];
31: undefined auStack2376 [2312];
32: long lStack64;
33: 
34: iVar8 = *(int *)(param_1 + 0x1e);
35: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
36: if (iVar8 < 1) {
37: ppcVar2 = (code **)*param_1;
38: ppcVar2[5] = (code *)0x13;
39: puStack2736 = (undefined *)0x11e260;
40: (**ppcVar2)();
41: iVar8 = *(int *)(param_1 + 0x1e);
42: }
43: piVar13 = (int *)param_1[0x1f];
44: iVar9 = *(int *)((long)param_1 + 0x4c);
45: if ((piVar13[5] == 0) && (piVar13[6] == 0x3f)) {
46: *(undefined4 *)((long)param_1 + 0x134) = 0;
47: if (iVar9 < 1) {
48: joined_r0x0011e803:
49: if (iVar8 < 1) goto LAB_0011e5b9;
50: LAB_0011e323:
51: piStack2696 = aiStack2632;
52: iVar8 = 1;
53: LAB_0011e338:
54: do {
55: iVar9 = *piVar13;
56: uStack2712 = uStack2712 & 0xffffffff00000000 | (ulong)(iVar9 - 1U);
57: iStack2704 = iVar9;
58: if (iVar9 - 1U < 4) {
59: LAB_0011e370:
60: iVar9 = piVar13[1];
61: piVar11 = piVar13 + 1;
62: if ((iVar9 < 0) ||
63: (*(int *)((long)param_1 + 0x4c) == iVar9 || *(int *)((long)param_1 + 0x4c) < iVar9)) {
64: ppcVar2 = (code **)*param_1;
65: *(undefined4 *)(ppcVar2 + 5) = 0x13;
66: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
67: puStack2736 = (undefined *)0x11e392;
68: (**ppcVar2)();
69: }
70: if (iStack2704 != 1) {
71: uVar1 = iStack2704 - 2;
72: do {
73: iVar9 = piVar11[1];
74: if ((iVar9 < 0) ||
75: (*(int *)((long)param_1 + 0x4c) == iVar9 || *(int *)((long)param_1 + 0x4c) < iVar9)
76: ) {
77: ppcVar2 = (code **)*param_1;
78: *(undefined4 *)(ppcVar2 + 5) = 0x13;
79: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
80: puStack2736 = (undefined *)0x11e3c2;
81: (**ppcVar2)();
82: }
83: if (iVar9 <= *piVar11) {
84: ppcVar2 = (code **)*param_1;
85: *(undefined4 *)(ppcVar2 + 5) = 0x13;
86: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
87: puStack2736 = (undefined *)0x11e3d9;
88: (**ppcVar2)();
89: }
90: piVar11 = piVar11 + 1;
91: } while (piVar11 != piVar13 + (ulong)uVar1 + 2);
92: }
93: }
94: else {
95: ppcVar2 = (code **)*param_1;
96: *(undefined4 *)(ppcVar2 + 5) = 0x1a;
97: *(int *)((long)ppcVar2 + 0x2c) = iVar9;
98: *(undefined4 *)(ppcVar2 + 6) = 4;
99: puStack2736 = (undefined *)0x11e367;
100: (**ppcVar2)();
101: if (0 < iVar9) goto LAB_0011e370;
102: }
103: uStack2688 = piVar13[5];
104: iStack2700 = piVar13[6];
105: uStack2716 = piVar13[7];
106: uVar1 = piVar13[8];
107: if (*(int *)((long)param_1 + 0x134) != 0) {
108: if ((((0x3f < uStack2688) || (iStack2700 < (int)uStack2688)) || (0x3f < iStack2700)) ||
109: ((10 < uStack2716 || (10 < uVar1)))) {
110: ppcVar2 = (code **)*param_1;
111: *(undefined4 *)(ppcVar2 + 5) = 0x11;
112: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
113: puStack2736 = (undefined *)0x11e441;
114: (**ppcVar2)();
115: }
116: if (uStack2688 == 0) {
117: if (iStack2700 != 0) {
118: LAB_0011e457:
119: ppcVar2 = (code **)*param_1;
120: *(undefined4 *)(ppcVar2 + 5) = 0x11;
121: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
122: puStack2736 = (undefined *)0x11e469;
123: (**ppcVar2)();
124: }
125: if (iStack2704 < 1) goto LAB_0011e54e;
126: }
127: else {
128: if (iStack2704 != 1) goto LAB_0011e457;
129: }
130: uStack2712 = 0;
131: uStack2684 = uStack2716 - 1;
132: do {
133: piVar11 = piStack2696 + (long)piVar13[uStack2712 + 1] * 0x40;
134: uVar6 = 0;
135: if ((uStack2688 != 0) &&
136: (uVar6 = uStack2688, aiStack2632[(long)piVar13[uStack2712 + 1] * 0x40] < 0)) {
137: ppcVar2 = (code **)*param_1;
138: *(undefined4 *)(ppcVar2 + 5) = 0x11;
139: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
140: puStack2736 = (undefined *)0x11e4d2;
141: (**ppcVar2)();
142: }
143: if ((int)uVar6 <= iStack2700) {
144: puVar12 = (uint *)(piVar11 + (int)uVar6);
145: uVar4 = iStack2700 - uVar6;
146: if (uStack2716 == 0) {
147: do {
148: if ((-1 < (int)*puVar12) && ((*puVar12 != 0 || (uVar1 != 0xffffffff)))) {
149: ppcVar2 = (code **)*param_1;
150: *(undefined4 *)(ppcVar2 + 5) = 0x11;
151: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
152: puStack2736 = (undefined *)0x11e609;
153: (**ppcVar2)();
154: }
155: *puVar12 = uVar1;
156: puVar12 = puVar12 + 1;
157: } while ((uint *)(piVar11 + (ulong)uVar4 + (long)(int)uVar6 + 1) != puVar12);
158: }
159: else {
160: do {
161: if ((((int)*puVar12 < 0) || (*puVar12 != uStack2716)) || (uStack2684 != uVar1)) {
162: ppcVar2 = (code **)*param_1;
163: *(undefined4 *)(ppcVar2 + 5) = 0x11;
164: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
165: puStack2736 = (undefined *)0x11e52c;
166: (**ppcVar2)();
167: }
168: *puVar12 = uVar1;
169: puVar12 = puVar12 + 1;
170: } while ((uint *)(piVar11 + (ulong)uVar4 + (long)(int)uVar6 + 1) != puVar12);
171: }
172: }
173: uStack2712 = uStack2712 + 1;
174: } while ((int)uStack2712 < iStack2704);
175: LAB_0011e54e:
176: piVar13 = piVar13 + 9;
177: iVar8 = iVar8 + 1;
178: if (*(int *)(param_1 + 0x1e) < iVar8) break;
179: goto LAB_0011e338;
180: }
181: if (((uStack2688 != 0) || (iStack2700 != 0x3f)) || ((uStack2716 | uVar1) != 0)) {
182: ppcVar2 = (code **)*param_1;
183: *(undefined4 *)(ppcVar2 + 5) = 0x11;
184: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
185: puStack2736 = (undefined *)0x11e657;
186: (**ppcVar2)();
187: }
188: if (iStack2704 < 1) goto LAB_0011e54e;
189: uVar14 = uStack2712 & 0xffffffff;
190: piVar11 = piVar13 + 1;
191: do {
192: lVar10 = (long)*piVar11;
193: iVar9 = aiStack2680[lVar10];
194: while (iVar9 != 0) {
195: ppcVar2 = (code **)*param_1;
196: piVar11 = piVar11 + 1;
197: *(undefined4 *)(ppcVar2 + 5) = 0x13;
198: *(int *)((long)ppcVar2 + 0x2c) = iVar8;
199: puStack2736 = (undefined *)0x11e694;
200: (**ppcVar2)();
201: aiStack2680[lVar10] = 1;
202: if (piVar11 == piVar13 + uVar14 + 2) goto LAB_0011e54e;
203: lVar10 = (long)*piVar11;
204: iVar9 = aiStack2680[lVar10];
205: }
206: piVar11 = piVar11 + 1;
207: aiStack2680[lVar10] = 1;
208: } while (piVar13 + uVar14 + 2 != piVar11);
209: piVar13 = piVar13 + 9;
210: iVar8 = iVar8 + 1;
211: } while (iVar8 <= *(int *)(param_1 + 0x1e));
212: iVar9 = *(int *)((long)param_1 + 0x4c);
213: if (*(int *)((long)param_1 + 0x134) != 0) {
214: if (iVar9 < 1) goto LAB_0011e5b9;
215: goto LAB_0011e576;
216: }
217: if (iVar9 < 1) goto LAB_0011e5b9;
218: }
219: else {
220: puStack2736 = (undefined *)0x11e72c;
221: memset(aiStack2680,0,(ulong)(iVar9 - 1) * 4 + 4);
222: if (0 < iVar8) goto LAB_0011e323;
223: }
224: lVar10 = 1;
225: do {
226: iVar8 = aiStack2680[lVar10 + -1];
227: lVar3 = lVar10;
228: while (iVar8 == 0) {
229: ppcVar2 = (code **)*param_1;
230: *(undefined4 *)(ppcVar2 + 5) = 0x2d;
231: puStack2736 = (undefined *)0x11e77f;
232: (**ppcVar2)(param_1);
233: iVar9 = *(int *)((long)param_1 + 0x4c);
234: if (iVar9 <= (int)lVar3) goto LAB_0011e5b9;
235: iVar8 = aiStack2680[lVar3];
236: lVar3 = lVar3 + 1;
237: }
238: lVar10 = lVar3 + 1;
239: } while ((int)lVar3 < iVar9);
240: }
241: else {
242: *(undefined4 *)((long)param_1 + 0x134) = 1;
243: if (iVar9 < 1) goto joined_r0x0011e803;
244: pauVar5 = (undefined (*) [16])aiStack2632;
245: pauVar7 = (undefined (*) [16])auStack2376;
246: while( true ) {
247: *pauVar5 = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
248: pauVar5[1] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
249: pauVar5[2] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
250: pauVar5[3] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
251: pauVar5[4] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
252: pauVar5[5] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
253: pauVar5[6] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
254: pauVar5[7] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
255: pauVar5[8] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
256: pauVar5[9] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
257: pauVar5[10] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
258: pauVar5[0xb] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
259: pauVar5[0xc] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
260: pauVar5[0xd] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
261: pauVar5[0xe] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
262: pauVar5[0xf] = CONCAT412(0xffffffff,CONCAT48(0xffffffff,0xffffffffffffffff));
263: if (pauVar7 == ((undefined (*) [16])auStack2376)[(ulong)(iVar9 - 1) * 0x10]) break;
264: pauVar5 = pauVar7;
265: pauVar7 = pauVar7[0x10];
266: }
267: if (0 < iVar8) goto LAB_0011e323;
268: LAB_0011e576:
269: lVar10 = 1;
270: do {
271: while (iVar8 = (int)lVar10, aiStack2888[lVar10 * 0x40] < 0) {
272: ppcVar2 = (code **)*param_1;
273: *(undefined4 *)(ppcVar2 + 5) = 0x2d;
274: puStack2736 = (undefined *)0x11e5ab;
275: (**ppcVar2)(param_1);
276: iVar9 = *(int *)((long)param_1 + 0x4c);
277: lVar10 = lVar10 + 1;
278: if (iVar9 <= iVar8) goto LAB_0011e5b9;
279: }
280: lVar10 = lVar10 + 1;
281: } while (iVar8 < iVar9);
282: }
283: LAB_0011e5b9:
284: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
285: return;
286: }
287: /* WARNING: Subroutine does not return */
288: puStack2736 = &UNK_0011e813;
289: __stack_chk_fail();
290: }
291: 
