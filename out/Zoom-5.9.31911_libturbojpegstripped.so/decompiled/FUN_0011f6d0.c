1: 
2: ulong FUN_0011f6d0(long param_1,long param_2)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: long lVar3;
8: ushort *puVar4;
9: code *pcVar5;
10: short *psVar6;
11: bool bVar7;
12: uint uVar8;
13: int iVar9;
14: int iVar10;
15: ulong uVar11;
16: long lVar12;
17: long lVar13;
18: uint uVar14;
19: long lVar15;
20: short *psVar16;
21: short sVar17;
22: uint uVar18;
23: long lVar19;
24: long lVar20;
25: int iVar21;
26: long lVar22;
27: long lVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: long lVar27;
32: int iVar28;
33: long lVar29;
34: int iVar30;
35: int iVar31;
36: long lVar32;
37: int iStack324;
38: long lStack320;
39: int iStack312;
40: int iStack308;
41: int iStack292;
42: short *psStack288;
43: short *psStack280;
44: int iStack272;
45: int iStack268;
46: long lStack264;
47: uint uStack204;
48: long *plStack200;
49: uint uStack104;
50: long lStack88;
51: int iStack64;
52: 
53: lVar2 = *(long *)(param_1 + 0x230);
54: iVar1 = *(int *)(param_1 + 0x1a4);
55: lVar3 = *(long *)(lVar2 + 0x88);
56: while( true ) {
57: if ((*(int *)(param_1 + 0xb4) < *(int *)(param_1 + 0xac)) ||
58: (*(int *)((long)*(code ***)(param_1 + 0x240) + 0x24) != 0)) break;
59: if ((*(int *)(param_1 + 0xac) == *(int *)(param_1 + 0xb4)) &&
60: (uVar18 = *(uint *)(param_1 + 0xb8), uVar8 = (*(int *)(param_1 + 0x20c) == 0) + uVar18,
61: uVar8 <= *(uint *)(param_1 + 0xb0) && *(uint *)(param_1 + 0xb0) != uVar8)) goto LAB_0011f777;
62: uVar11 = (***(code ***)(param_1 + 0x240))();
63: if ((int)uVar11 == 0) {
64: return uVar11;
65: }
66: }
67: uVar18 = *(uint *)(param_1 + 0xb8);
68: LAB_0011f777:
69: lStack320 = *(long *)(param_1 + 0x130);
70: iVar9 = *(int *)(param_1 + 0x38);
71: if (0 < iVar9) {
72: lStack88 = 0;
73: iStack64 = 0;
74: do {
75: if (*(int *)(lStack320 + 0x30) != 0) {
76: if (uVar18 < iVar1 - 1U) {
77: uVar8 = *(uint *)(lStack320 + 0xc);
78: bVar7 = false;
79: uStack104 = uVar8;
80: }
81: else {
82: uVar8 = *(uint *)(lStack320 + 0xc);
83: uStack104 = *(uint *)(lStack320 + 0x20) % uVar8;
84: if (uStack104 == 0) {
85: bVar7 = true;
86: uStack104 = uVar8;
87: }
88: else {
89: bVar7 = true;
90: }
91: }
92: if (uVar18 == 0) {
93: plStack200 = (long *)(**(code **)(*(long *)(param_1 + 8) + 0x40))
94: (param_1,*(undefined8 *)(lVar2 + 0x90 + lStack88),0);
95: }
96: else {
97: lVar12 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
98: (param_1,*(undefined8 *)(lVar2 + 0x90 + lStack88),(uVar18 - 1) * uVar8)
99: ;
100: plStack200 = (long *)(lVar12 + (long)*(int *)(lStack320 + 0xc) * 8);
101: }
102: lVar12 = (long)iStack64;
103: lVar32 = lStack88 * 3 + *(long *)(lVar2 + 0xe0);
104: puVar4 = *(ushort **)(lStack320 + 0x50);
105: uVar11 = (ulong)*puVar4;
106: pcVar5 = *(code **)(*(long *)(param_1 + 600) + 8 + lVar12 * 8);
107: lStack264 = *(long *)(param_2 + lStack88);
108: if (0 < (int)uStack104) {
109: uStack204 = 0;
110: lVar13 = *(long *)(param_1 + 0x220);
111: lVar25 = (ulong)puVar4[1] * 0x80;
112: lVar29 = (ulong)puVar4[1] << 8;
113: lVar24 = (ulong)puVar4[8] << 8;
114: lVar26 = (ulong)puVar4[8] * 0x80;
115: uVar8 = *(uint *)(lVar13 + 0x44 + lVar12 * 4);
116: lVar22 = (ulong)puVar4[0x10] << 8;
117: lVar27 = (ulong)puVar4[0x10] * 0x80;
118: lVar19 = (ulong)puVar4[9] << 8;
119: lVar15 = (ulong)puVar4[2] << 8;
120: lVar23 = (ulong)puVar4[9] * 0x80;
121: lVar20 = (ulong)puVar4[2] * 0x80;
122: do {
123: uVar14 = *(uint *)(lVar13 + 0x1c + lVar12 * 4);
124: psVar6 = (short *)((ulong)uVar14 * 0x80 + *plStack200);
125: if ((uStack204 != 0) || (psStack288 = psVar6, uVar18 != 0)) {
126: psStack288 = (short *)plStack200[-1];
127: }
128: if ((!bVar7) || (psStack280 = psVar6, uStack104 - 1 != uStack204)) {
129: psStack280 = (short *)plStack200[1];
130: }
131: iStack272 = (int)*psVar6;
132: iVar9 = *(int *)(lStack320 + 0x1c);
133: if (uVar8 < uVar14) {
134: iVar21 = *(int *)(lStack320 + 0x24);
135: }
136: else {
137: psVar16 = psVar6 + 0x40;
138: iStack312 = (int)*psStack288;
139: iStack308 = (int)*psStack280;
140: iStack324 = iStack272;
141: iStack292 = (int)*psStack288;
142: iStack268 = (int)*psStack280;
143: while( true ) {
144: iVar31 = iStack308;
145: iVar30 = iStack312;
146: psStack280 = psStack280 + 0x40;
147: psStack288 = psStack288 + 0x40;
148: FUN_0013beb0(psVar16 + -0x40,lVar3,1);
149: iVar28 = iStack324;
150: iStack312 = iVar30;
151: iStack308 = iVar31;
152: if (uVar14 < iVar9 - 1U) {
153: iVar28 = (int)*(short *)((long)psVar16 + (-0x80 - (long)psVar6) +
154: (long)(psVar6 + 0x40));
155: iStack312 = (int)*psStack288;
156: iStack308 = (int)*psStack280;
157: }
158: iVar21 = *(int *)(lVar32 + 4);
159: if ((iVar21 != 0) && (*(short *)(lVar3 + 2) == 0)) {
160: lVar13 = (long)(iStack272 - iVar28) * uVar11 * 0x24;
161: if (lVar13 < 0) {
162: iVar10 = (int)((lVar25 - lVar13) / lVar29);
163: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= iVar10)) {
164: iVar10 = iVar21 + -1;
165: }
166: sVar17 = -(short)iVar10;
167: }
168: else {
169: lVar13 = (lVar13 + lVar25) / lVar29;
170: sVar17 = (short)lVar13;
171: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= (int)lVar13)
172: ) {
173: sVar17 = (short)iVar21 + -1;
174: }
175: }
176: *(short *)(lVar3 + 2) = sVar17;
177: }
178: iVar21 = *(int *)(lVar32 + 8);
179: if ((iVar21 != 0) && (*(short *)(lVar3 + 0x10) == 0)) {
180: lVar13 = (long)(iVar30 - iVar31) * uVar11 * 0x24;
181: if (lVar13 < 0) {
182: iVar10 = (int)((lVar26 - lVar13) / lVar24);
183: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= iVar10)) {
184: iVar10 = iVar21 + -1;
185: }
186: sVar17 = -(short)iVar10;
187: }
188: else {
189: lVar13 = (lVar13 + lVar26) / lVar24;
190: sVar17 = (short)lVar13;
191: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= (int)lVar13)
192: ) {
193: sVar17 = (short)iVar21 + -1;
194: }
195: }
196: *(short *)(lVar3 + 0x10) = sVar17;
197: }
198: iVar21 = *(int *)(lVar32 + 0xc);
199: if ((iVar21 != 0) && (*(short *)(lVar3 + 0x20) == 0)) {
200: lVar13 = (long)(iVar30 + iVar31 + iStack324 * -2) * uVar11 * 9;
201: if (lVar13 < 0) {
202: iVar10 = (int)((lVar27 - lVar13) / lVar22);
203: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= iVar10)) {
204: iVar10 = iVar21 + -1;
205: }
206: sVar17 = -(short)iVar10;
207: }
208: else {
209: lVar13 = (lVar13 + lVar27) / lVar22;
210: sVar17 = (short)lVar13;
211: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= (int)lVar13)
212: ) {
213: sVar17 = (short)iVar21 + -1;
214: }
215: }
216: *(short *)(lVar3 + 0x20) = sVar17;
217: }
218: iVar21 = *(int *)(lVar32 + 0x10);
219: if ((iVar21 != 0) && (*(short *)(lVar3 + 0x12) == 0)) {
220: lVar13 = (long)(((iStack292 - iStack312) - iStack268) + iStack308) * uVar11 * 5;
221: if (lVar13 < 0) {
222: iVar10 = (int)((lVar23 - lVar13) / lVar19);
223: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= iVar10)) {
224: iVar10 = iVar21 + -1;
225: }
226: sVar17 = -(short)iVar10;
227: }
228: else {
229: lVar13 = (lVar13 + lVar23) / lVar19;
230: sVar17 = (short)lVar13;
231: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= (int)lVar13)
232: ) {
233: sVar17 = (short)iVar21 + -1;
234: }
235: }
236: *(short *)(lVar3 + 0x12) = sVar17;
237: }
238: iVar21 = *(int *)(lVar32 + 0x14);
239: if ((iVar21 != 0) && (*(short *)(lVar3 + 4) == 0)) {
240: lVar13 = (long)(iStack272 + iVar28 + iStack324 * -2) * uVar11 * 9;
241: if (lVar13 < 0) {
242: iVar10 = (int)((lVar20 - lVar13) / lVar15);
243: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= iVar10)) {
244: iVar10 = iVar21 + -1;
245: }
246: sVar17 = -(short)iVar10;
247: }
248: else {
249: lVar13 = (lVar13 + lVar20) / lVar15;
250: sVar17 = (short)lVar13;
251: if ((0 < iVar21) && (iVar21 = 1 << ((byte)iVar21 & 0x1f), iVar21 <= (int)lVar13)
252: ) {
253: sVar17 = (short)iVar21 + -1;
254: }
255: }
256: *(short *)(lVar3 + 4) = sVar17;
257: }
258: uVar14 = uVar14 + 1;
259: psVar16 = psVar16 + 0x40;
260: (*pcVar5)(param_1,lStack320,lVar3,lStack264);
261: iVar21 = *(int *)(lStack320 + 0x24);
262: lVar13 = *(long *)(param_1 + 0x220);
263: uVar8 = *(uint *)(lVar13 + 0x44 + lVar12 * 4);
264: if (uVar8 < uVar14) break;
265: iStack272 = iStack324;
266: iStack324 = iVar28;
267: iStack292 = iVar30;
268: iStack268 = iVar31;
269: }
270: }
271: uStack204 = uStack204 + 1;
272: plStack200 = plStack200 + 1;
273: lStack264 = lStack264 + (long)iVar21 * 8;
274: } while (uStack204 != uStack104);
275: }
276: iVar9 = *(int *)(param_1 + 0x38);
277: uVar18 = *(uint *)(param_1 + 0xb8);
278: }
279: iStack64 = iStack64 + 1;
280: lStack320 = lStack320 + 0x60;
281: lStack88 = lStack88 + 8;
282: } while (iStack64 < iVar9);
283: }
284: *(uint *)(param_1 + 0xb8) = uVar18 + 1;
285: return (ulong)(4 - (uVar18 + 1 < *(uint *)(param_1 + 0x1a4)));
286: }
287: 
