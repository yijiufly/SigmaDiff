1: 
2: void FUN_00133c20(code **param_1,int param_2)
3: 
4: {
5: undefined4 *puVar1;
6: undefined8 *puVar2;
7: undefined8 *puVar3;
8: undefined8 *puVar4;
9: undefined8 *puVar5;
10: undefined4 *puVar6;
11: int iVar7;
12: code *pcVar8;
13: long lVar9;
14: long lVar10;
15: undefined8 *puVar11;
16: undefined8 uVar12;
17: undefined4 uVar13;
18: undefined4 uVar14;
19: undefined4 uVar15;
20: undefined4 uVar16;
21: uint uVar17;
22: code *pcVar18;
23: undefined8 *puVar19;
24: undefined8 *puVar20;
25: int iVar21;
26: int iVar22;
27: long lVar23;
28: long lVar24;
29: uint uVar25;
30: long lVar26;
31: long lVar27;
32: uint uVar28;
33: int iVar29;
34: uint uVar30;
35: int iVar31;
36: uint uVar32;
37: code *pcVar33;
38: bool bVar34;
39: long lStack112;
40: 
41: pcVar8 = param_1[0x45];
42: if (param_2 == 0) {
43: if (*(int *)(param_1[0x4c] + 0x10) == 0) {
44: *(code **)(pcVar8 + 8) = FUN_00133730;
45: }
46: else {
47: iVar7 = *(int *)(param_1 + 0x34);
48: pcVar33 = param_1[0x26];
49: *(code **)(pcVar8 + 8) = FUN_001337d0;
50: if (0 < *(int *)(param_1 + 7)) {
51: lVar9 = *(long *)(pcVar8 + 0x68);
52: lVar10 = *(long *)(pcVar8 + 0x70);
53: lStack112 = 0;
54: pcVar18 = pcVar33 + ((ulong)(*(int *)(param_1 + 7) - 1) * 3 + 3) * 0x20;
55: do {
56: uVar17 = (*(int *)(pcVar33 + 0xc) * *(int *)(pcVar33 + 0x24)) / iVar7;
57: uVar30 = (iVar7 + 2) * uVar17;
58: puVar19 = *(undefined8 **)(lVar10 + lStack112);
59: puVar11 = *(undefined8 **)(lVar9 + lStack112);
60: puVar20 = *(undefined8 **)(pcVar8 + lStack112 + 0x10);
61: if (0 < (int)uVar30) {
62: if (((puVar19 < puVar20 + 2 && puVar20 < puVar19 + 2 ||
63: puVar11 < puVar20 + 2 && puVar20 < puVar11 + 2) ||
64: puVar19 < puVar11 + 2 && puVar11 < puVar19 + 2) || (uVar30 < 0x1d)) {
65: lVar23 = 0;
66: do {
67: uVar12 = *(undefined8 *)((long)puVar20 + lVar23);
68: *(undefined8 *)((long)puVar19 + lVar23) = uVar12;
69: *(undefined8 *)((long)puVar11 + lVar23) = uVar12;
70: lVar23 = lVar23 + 8;
71: } while (lVar23 != (ulong)(uVar30 - 1) * 8 + 8);
72: }
73: else {
74: uVar25 = (uint)((ulong)puVar20 >> 3) & 1;
75: bVar34 = ((ulong)puVar20 >> 3 & 1) != 0;
76: if (bVar34) {
77: uVar12 = *puVar20;
78: *puVar19 = uVar12;
79: *puVar11 = uVar12;
80: }
81: lVar23 = 0;
82: uVar28 = 0;
83: uVar32 = uVar30 - uVar25;
84: lVar26 = (ulong)uVar25 * 8;
85: do {
86: puVar1 = (undefined4 *)((long)puVar20 + lVar23 + lVar26);
87: uVar13 = *puVar1;
88: uVar14 = puVar1[1];
89: uVar15 = puVar1[2];
90: uVar16 = puVar1[3];
91: uVar28 = uVar28 + 1;
92: puVar1 = (undefined4 *)((long)puVar19 + lVar23 + lVar26);
93: *puVar1 = uVar13;
94: puVar1[1] = uVar14;
95: puVar1[2] = uVar15;
96: puVar1[3] = uVar16;
97: puVar1 = (undefined4 *)((long)puVar11 + lVar23 + lVar26);
98: *puVar1 = uVar13;
99: puVar1[1] = uVar14;
100: puVar1[2] = uVar15;
101: puVar1[3] = uVar16;
102: lVar23 = lVar23 + 0x10;
103: } while (uVar28 < uVar32 >> 1);
104: iVar29 = (uint)bVar34 + (uVar32 & 0xfffffffe);
105: if (uVar32 != (uVar32 & 0xfffffffe)) {
106: lVar23 = (long)iVar29;
107: iVar29 = iVar29 + 1;
108: uVar12 = puVar20[lVar23];
109: puVar19[lVar23] = uVar12;
110: puVar11[lVar23] = uVar12;
111: if (iVar29 < (int)uVar30) {
112: lVar23 = (long)iVar29;
113: uVar12 = puVar20[lVar23];
114: puVar19[lVar23] = uVar12;
115: puVar11[lVar23] = uVar12;
116: }
117: }
118: }
119: }
120: uVar25 = uVar17 * 2;
121: if (0 < (int)uVar25) {
122: iVar31 = uVar30 + uVar17 * -2;
123: lVar24 = (long)iVar31;
124: lVar23 = lVar24 * 8 + 0x10;
125: iVar29 = iVar31 + uVar17 * -2;
126: puVar2 = puVar19 + lVar24;
127: puVar3 = puVar20 + lVar24;
128: lVar27 = (long)iVar29;
129: lVar26 = lVar27 * 8;
130: puVar4 = puVar19 + lVar27;
131: puVar5 = puVar20 + lVar27;
132: if (((puVar5 < puVar19 + lVar24 + 2 && puVar2 < puVar20 + lVar27 + 2 ||
133: ((puVar2 < puVar20 + lVar24 + 2 && puVar3 < puVar19 + lVar24 + 2 ||
134: puVar4 < puVar20 + lVar24 + 2 && puVar3 < puVar19 + lVar27 + 2) || uVar25 < 0x21))
135: || (lVar23 != lVar26 && SBORROW8(lVar23,lVar26) == lVar23 + lVar27 * -8 < 0) &&
136: lVar24 * 8 < lVar27 * 8 + 0x10) ||
137: (puVar4 < puVar20 + lVar27 + 2 && puVar5 < puVar19 + lVar27 + 2)) {
138: lVar23 = 0;
139: do {
140: *(undefined8 *)((long)puVar4 + lVar23) = *(undefined8 *)((long)puVar3 + lVar23);
141: *(undefined8 *)((long)puVar2 + lVar23) = *(undefined8 *)((long)puVar5 + lVar23);
142: lVar23 = lVar23 + 8;
143: } while (lVar23 != (ulong)(uVar25 - 1) * 8 + 8);
144: }
145: else {
146: uVar30 = (uint)((ulong)puVar3 >> 3) & 1;
147: bVar34 = ((ulong)puVar3 >> 3 & 1) != 0;
148: if (bVar34) {
149: *puVar4 = *puVar3;
150: *puVar2 = *puVar5;
151: }
152: uVar28 = 0;
153: uVar32 = uVar25 - uVar30;
154: lVar23 = (ulong)uVar30 * 8;
155: lVar24 = lVar24 * 8 + lVar23;
156: lVar26 = lVar26 + lVar23;
157: lVar23 = 0;
158: do {
159: puVar6 = (undefined4 *)((long)puVar20 + lVar23 + lVar24);
160: uVar13 = puVar6[1];
161: uVar14 = puVar6[2];
162: uVar15 = puVar6[3];
163: uVar28 = uVar28 + 1;
164: puVar1 = (undefined4 *)((long)puVar19 + lVar23 + lVar26);
165: *puVar1 = *puVar6;
166: puVar1[1] = uVar13;
167: puVar1[2] = uVar14;
168: puVar1[3] = uVar15;
169: puVar1 = (undefined4 *)((long)puVar20 + lVar23 + lVar26);
170: uVar13 = puVar1[1];
171: uVar14 = puVar1[2];
172: uVar15 = puVar1[3];
173: puVar6 = (undefined4 *)((long)puVar19 + lVar23 + lVar24);
174: *puVar6 = *puVar1;
175: puVar6[1] = uVar13;
176: puVar6[2] = uVar14;
177: puVar6[3] = uVar15;
178: lVar23 = lVar23 + 0x10;
179: } while (uVar28 < uVar32 >> 1);
180: iVar21 = (uint)bVar34 + (uVar32 & 0xfffffffe);
181: if (uVar32 != (uVar32 & 0xfffffffe)) {
182: iVar22 = iVar21 + 1;
183: puVar19[iVar29 + iVar21] = puVar20[iVar31 + iVar21];
184: puVar19[iVar31 + iVar21] = puVar20[iVar29 + iVar21];
185: if (iVar22 < (int)uVar25) {
186: puVar19[iVar22 + iVar29] = puVar20[iVar31 + iVar22];
187: puVar19[iVar31 + iVar22] = puVar20[iVar22 + iVar29];
188: }
189: }
190: }
191: }
192: if (0 < (int)uVar17) {
193: lVar23 = (long)(int)-uVar17;
194: puVar19 = puVar11 + lVar23;
195: if ((((int)uVar17 + lVar23) * 8 < 1 || puVar11 + 1 <= puVar19) && (0x18 < uVar17)) {
196: uVar30 = (uint)((ulong)puVar19 >> 3) & 1;
197: bVar34 = ((ulong)puVar19 >> 3 & 1) != 0;
198: if (bVar34) {
199: *puVar19 = *puVar11;
200: }
201: uVar12 = *puVar11;
202: uVar28 = uVar17 - uVar30;
203: uVar25 = 0;
204: puVar19 = puVar11 + (ulong)uVar30 + lVar23;
205: do {
206: uVar25 = uVar25 + 1;
207: *puVar19 = uVar12;
208: puVar19[1] = uVar12;
209: puVar19 = puVar19 + 2;
210: } while (uVar25 < uVar28 >> 1);
211: iVar29 = (uint)bVar34 + (uVar28 & 0xfffffffe);
212: if (uVar28 != (uVar28 & 0xfffffffe)) {
213: iVar31 = iVar29 + 1;
214: puVar11[(int)(iVar29 - uVar17)] = *puVar11;
215: if (iVar31 < (int)uVar17) {
216: puVar11[(int)(iVar31 - uVar17)] = *puVar11;
217: }
218: }
219: }
220: else {
221: do {
222: puVar20 = puVar19 + 1;
223: *puVar19 = *puVar11;
224: puVar19 = puVar20;
225: } while (puVar20 != puVar11 + 1 + lVar23 + (ulong)(uVar17 - 1));
226: }
227: }
228: pcVar33 = pcVar33 + 0x60;
229: lStack112 = lStack112 + 8;
230: } while (pcVar33 != pcVar18);
231: }
232: *(undefined8 *)(pcVar8 + 0x78) = 0;
233: *(undefined4 *)(pcVar8 + 0x84) = 0;
234: }
235: *(undefined8 *)(pcVar8 + 0x60) = 0;
236: return;
237: }
238: if (param_2 != 2) {
239: param_1 = (code **)*param_1;
240: *(undefined4 *)(param_1 + 5) = 4;
241: /* WARNING: Could not recover jumptable at 0x00133c6f. Too many branches */
242: /* WARNING: Treating indirect jump as call */
243: (**param_1)();
244: return;
245: }
246: *(code **)(pcVar8 + 8) = FUN_00133c00;
247: return;
248: }
249: 
