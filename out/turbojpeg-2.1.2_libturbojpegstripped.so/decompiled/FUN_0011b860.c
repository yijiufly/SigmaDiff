1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0011b860(code **param_1,undefined8 *param_2,long param_3)
5: 
6: {
7: long *plVar1;
8: long *plVar2;
9: char *pcVar3;
10: char cVar4;
11: code **ppcVar5;
12: ulong uVar6;
13: long lVar7;
14: int iVar8;
15: long lVar9;
16: long lVar10;
17: int iVar11;
18: ulong uVar12;
19: char *pcVar13;
20: undefined8 *puVar14;
21: undefined8 *puVar15;
22: long in_FS_OFFSET;
23: undefined8 auStack2184 [128];
24: int aiStack1156 [3];
25: undefined8 auStack1144 [130];
26: undefined auStack104 [9];
27: char cStack95;
28: char cStack94;
29: char cStack93;
30: char cStack92;
31: char cStack91;
32: char cStack90;
33: char cStack89;
34: undefined auStack88 [16];
35: char acStack72 [8];
36: long lStack64;
37: 
38: lVar9 = 0x80;
39: puVar15 = auStack2184;
40: *(undefined8 *)(param_3 + 0x800) = 1;
41: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
42: acStack72[0] = 0;
43: puVar14 = auStack2184;
44: while (lVar9 != 0) {
45: lVar9 = lVar9 + -1;
46: *puVar14 = 0;
47: puVar14 = puVar14 + 1;
48: }
49: lVar9 = 0x80;
50: _auStack104 = (undefined  [16])0x0;
51: auStack88 = (undefined  [16])0x0;
52: *(undefined4 *)puVar14 = 0;
53: puVar14 = auStack1144;
54: while (lVar9 != 0) {
55: lVar9 = lVar9 + -1;
56: *puVar14 = 0xffffffffffffffff;
57: puVar14 = puVar14 + 1;
58: }
59: *(undefined4 *)puVar14 = 0xffffffff;
60: while( true ) {
61: uVar6 = 0;
62: lVar9 = 1000000000;
63: uVar12 = 0xffffffff;
64: do {
65: lVar7 = *(long *)(param_3 + uVar6 * 8);
66: if ((lVar7 != 0) && (lVar7 <= lVar9)) {
67: uVar12 = uVar6 & 0xffffffff;
68: lVar9 = lVar7;
69: }
70: uVar6 = uVar6 + 1;
71: } while (uVar6 != 0x101);
72: lVar7 = 0;
73: lVar9 = 1000000000;
74: iVar8 = -1;
75: do {
76: lVar10 = *(long *)(param_3 + lVar7 * 8);
77: if ((lVar10 == 0 || lVar9 < lVar10) || (iVar11 = (int)lVar7, (int)uVar12 == (int)lVar7)) {
78: lVar10 = lVar9;
79: iVar11 = iVar8;
80: }
81: iVar8 = iVar11;
82: lVar7 = lVar7 + 1;
83: lVar9 = lVar10;
84: } while (lVar7 != 0x101);
85: if (iVar8 < 0) break;
86: lVar9 = (long)(int)uVar12;
87: lVar7 = (long)iVar8;
88: plVar1 = (long *)(param_3 + lVar7 * 8);
89: puVar14 = (undefined8 *)((long)auStack2184 + lVar9 * 4);
90: *(int *)puVar14 = *(int *)puVar14 + 1;
91: plVar2 = (long *)(param_3 + lVar9 * 8);
92: *plVar2 = *plVar2 + *plVar1;
93: *plVar1 = 0;
94: iVar11 = *(int *)((long)auStack1144 + lVar9 * 4);
95: while (-1 < iVar11) {
96: lVar9 = (long)iVar11;
97: iVar11 = *(int *)((long)auStack1144 + lVar9 * 4);
98: puVar14 = (undefined8 *)((long)auStack2184 + lVar9 * 4);
99: *(int *)puVar14 = *(int *)puVar14 + 1;
100: }
101: *(int *)((long)auStack1144 + lVar9 * 4) = iVar8;
102: iVar8 = *(int *)((long)auStack1144 + lVar7 * 4);
103: puVar14 = (undefined8 *)((long)auStack2184 + lVar7 * 4);
104: *(int *)puVar14 = *(int *)puVar14 + 1;
105: while (-1 < iVar8) {
106: puVar14 = (undefined8 *)((long)auStack2184 + (long)iVar8 * 4);
107: *(int *)puVar14 = *(int *)puVar14 + 1;
108: iVar8 = *(int *)((long)auStack1144 + (long)iVar8 * 4);
109: }
110: }
111: do {
112: iVar8 = *(int *)puVar15;
113: if (iVar8 != 0) {
114: if (0x20 < iVar8) {
115: ppcVar5 = (code **)*param_1;
116: *(undefined4 *)(ppcVar5 + 5) = 0x27;
117: (**ppcVar5)();
118: }
119: auStack104[iVar8] = auStack104[iVar8] + '\x01';
120: }
121: puVar15 = (undefined8 *)((long)puVar15 + 4);
122: } while (puVar15 != (undefined8 *)aiStack1156);
123: pcVar13 = auStack88 + 0xe;
124: lVar9 = 0x1d;
125: do {
126: cVar4 = pcVar13[2];
127: while (cVar4 != '\0') {
128: lVar7 = lVar9;
129: iVar11 = (int)lVar9 + 2;
130: iVar8 = (int)lVar9 + 1;
131: if (*pcVar13 == '\0') {
132: do {
133: iVar8 = (int)lVar7;
134: pcVar3 = auStack104 + lVar7;
135: lVar7 = lVar7 + -1;
136: } while (*pcVar3 == '\0');
137: iVar11 = iVar8 + 1;
138: }
139: pcVar13[1] = pcVar13[1] + '\x01';
140: pcVar13[2] = cVar4 + -2;
141: auStack104[iVar11] = auStack104[iVar11] + '\x02';
142: auStack104[iVar8] = auStack104[iVar8] + -1;
143: cVar4 = pcVar13[2];
144: }
145: lVar9 = lVar9 + -1;
146: pcVar13 = pcVar13 + -1;
147: } while (lVar9 != 0xd);
148: lVar9 = 0x10;
149: if (auStack88[0] == '\0') {
150: cStack89 = SUB161(_auStack104 >> 0x78,0);
151: if (cStack89 == '\0') {
152: cStack90 = SUB161(_auStack104 >> 0x70,0);
153: if (cStack90 == '\0') {
154: cStack91 = SUB161(_auStack104 >> 0x68,0);
155: if (cStack91 == '\0') {
156: cStack92 = SUB161(_auStack104 >> 0x60,0);
157: if (cStack92 == '\0') {
158: cStack93 = SUB161(_auStack104 >> 0x58,0);
159: if (cStack93 == '\0') {
160: cStack94 = SUB161(_auStack104 >> 0x50,0);
161: if (cStack94 == '\0') {
162: cStack95 = SUB161(_auStack104 >> 0x48,0);
163: if (cStack95 == '\0') {
164: auStack104[8] = SUB161(_auStack104 >> 0x40,0);
165: if (auStack104[8] == '\0') {
166: auStack104[7] = SUB161(_auStack104 >> 0x38,0);
167: if (auStack104[7] == '\0') {
168: auStack104[6] = SUB161(_auStack104 >> 0x30,0);
169: if (auStack104[6] == '\0') {
170: auStack104[5] = SUB161(_auStack104 >> 0x28,0);
171: if (auStack104[5] == '\0') {
172: auStack104[4] = SUB161(_auStack104 >> 0x20,0);
173: if (auStack104[4] == '\0') {
174: auStack104[3] = SUB161(_auStack104 >> 0x18,0);
175: if (auStack104[3] == '\0') {
176: auStack104[2] = SUB161(_auStack104 >> 0x10,0);
177: if (auStack104[2] == '\0') {
178: auStack104[1] = SUB161(_auStack104 >> 8,0);
179: if (auStack104[1] == '\0') {
180: lVar9 = 0;
181: auStack88[0] = auStack104[0];
182: }
183: else {
184: lVar9 = 1;
185: auStack88[0] = auStack104[1];
186: }
187: }
188: else {
189: lVar9 = 2;
190: auStack88[0] = auStack104[2];
191: }
192: }
193: else {
194: lVar9 = 3;
195: auStack88[0] = auStack104[3];
196: }
197: }
198: else {
199: lVar9 = 4;
200: auStack88[0] = auStack104[4];
201: }
202: }
203: else {
204: lVar9 = 5;
205: auStack88[0] = auStack104[5];
206: }
207: }
208: else {
209: lVar9 = 6;
210: auStack88[0] = auStack104[6];
211: }
212: }
213: else {
214: lVar9 = 7;
215: auStack88[0] = auStack104[7];
216: }
217: }
218: else {
219: lVar9 = 8;
220: auStack88[0] = auStack104[8];
221: }
222: }
223: else {
224: lVar9 = 9;
225: auStack88[0] = cStack95;
226: }
227: }
228: else {
229: lVar9 = 10;
230: auStack88[0] = cStack94;
231: }
232: }
233: else {
234: lVar9 = 0xb;
235: auStack88[0] = cStack93;
236: }
237: }
238: else {
239: lVar9 = 0xc;
240: auStack88[0] = cStack92;
241: }
242: }
243: else {
244: lVar9 = 0xd;
245: auStack88[0] = cStack91;
246: }
247: }
248: else {
249: lVar9 = 0xe;
250: auStack88[0] = cStack90;
251: }
252: }
253: else {
254: lVar9 = 0xf;
255: auStack88[0] = cStack89;
256: }
257: }
258: iVar8 = 0;
259: auStack104[lVar9] = auStack88[0] + -1;
260: iVar11 = 1;
261: *param_2 = auStack104._0_8_;
262: param_2[1] = stack0xffffffffffffffa0;
263: *(char *)(param_2 + 2) = auStack88[0];
264: do {
265: lVar9 = 0;
266: do {
267: if (*(int *)((long)auStack2184 + lVar9 * 4) == iVar11) {
268: lVar7 = (long)iVar8;
269: iVar8 = iVar8 + 1;
270: *(char *)((long)param_2 + lVar7 + 0x11) = (char)lVar9;
271: }
272: lVar9 = lVar9 + 1;
273: } while (lVar9 != 0x100);
274: iVar11 = iVar11 + 1;
275: } while (iVar11 != 0x21);
276: lVar9 = *(long *)(in_FS_OFFSET + 0x28);
277: *(undefined4 *)((long)param_2 + 0x114) = 0;
278: if (lStack64 == lVar9) {
279: return;
280: }
281: /* WARNING: Subroutine does not return */
282: __stack_chk_fail(auStack104._0_8_);
283: }
284: 
