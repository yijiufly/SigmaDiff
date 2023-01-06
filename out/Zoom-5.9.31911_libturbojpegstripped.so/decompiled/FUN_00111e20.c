1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_00111e20(code **param_1,undefined8 *param_2,long param_3)
5: 
6: {
7: long *plVar1;
8: long *plVar2;
9: char *pcVar3;
10: char cVar4;
11: int iVar5;
12: ulong uVar6;
13: long lVar7;
14: undefined8 *puVar8;
15: char cVar9;
16: long lVar10;
17: int iVar11;
18: ulong uVar12;
19: ulong uVar13;
20: undefined8 *puVar14;
21: long in_FS_OFFSET;
22: undefined8 auStack2184 [128];
23: int aiStack1156 [3];
24: undefined8 auStack1144 [130];
25: undefined8 uStack104;
26: undefined8 uStack96;
27: undefined8 uStack88;
28: undefined8 uStack80;
29: undefined uStack72;
30: long lStack64;
31: 
32: lVar7 = 0x80;
33: puVar14 = auStack2184;
34: *(undefined8 *)(param_3 + 0x800) = 1;
35: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
36: uStack104 = 0;
37: puVar8 = auStack2184;
38: while (lVar7 != 0) {
39: lVar7 = lVar7 + -1;
40: *puVar8 = 0;
41: puVar8 = puVar8 + 1;
42: }
43: uStack96 = 0;
44: uStack88 = 0;
45: uStack80 = 0;
46: uStack72 = 0;
47: *(undefined4 *)puVar8 = 0;
48: lVar7 = 0x80;
49: puVar8 = auStack1144;
50: while (lVar7 != 0) {
51: lVar7 = lVar7 + -1;
52: *puVar8 = 0xffffffffffffffff;
53: puVar8 = puVar8 + 1;
54: }
55: *(undefined4 *)puVar8 = 0xffffffff;
56: while( true ) {
57: uVar6 = 0;
58: lVar7 = 1000000000;
59: uVar12 = 0xffffffff;
60: do {
61: lVar10 = *(long *)(param_3 + uVar6 * 8);
62: if ((lVar10 != 0) && (lVar10 <= lVar7)) {
63: uVar12 = uVar6 & 0xffffffff;
64: lVar7 = lVar10;
65: }
66: uVar6 = uVar6 + 1;
67: } while (uVar6 != 0x101);
68: uVar6 = 0;
69: lVar7 = 1000000000;
70: uVar13 = 0xffffffff;
71: do {
72: lVar10 = *(long *)(param_3 + uVar6 * 8);
73: if (((lVar10 != 0) && (lVar10 <= lVar7)) && ((int)uVar6 != (int)uVar12)) {
74: uVar13 = uVar6 & 0xffffffff;
75: lVar7 = lVar10;
76: }
77: uVar6 = uVar6 + 1;
78: } while (uVar6 != 0x101);
79: iVar11 = (int)uVar13;
80: if (iVar11 == -1) break;
81: lVar10 = (long)iVar11;
82: lVar7 = (long)(int)uVar12;
83: plVar1 = (long *)(param_3 + lVar10 * 8);
84: puVar8 = (undefined8 *)((long)auStack2184 + lVar7 * 4);
85: *(int *)puVar8 = *(int *)puVar8 + 1;
86: plVar2 = (long *)(param_3 + lVar7 * 8);
87: *plVar2 = *plVar2 + *plVar1;
88: *plVar1 = 0;
89: iVar5 = *(int *)((long)auStack1144 + lVar7 * 4);
90: while (-1 < iVar5) {
91: lVar7 = (long)iVar5;
92: iVar5 = *(int *)((long)auStack1144 + lVar7 * 4);
93: puVar8 = (undefined8 *)((long)auStack2184 + lVar7 * 4);
94: *(int *)puVar8 = *(int *)puVar8 + 1;
95: }
96: *(int *)((long)auStack1144 + lVar7 * 4) = iVar11;
97: iVar11 = *(int *)((long)auStack1144 + lVar10 * 4);
98: puVar8 = (undefined8 *)((long)auStack2184 + lVar10 * 4);
99: *(int *)puVar8 = *(int *)puVar8 + 1;
100: while (-1 < iVar11) {
101: puVar8 = (undefined8 *)((long)auStack2184 + (long)iVar11 * 4);
102: *(int *)puVar8 = *(int *)puVar8 + 1;
103: iVar11 = *(int *)((long)auStack1144 + (long)iVar11 * 4);
104: }
105: }
106: do {
107: iVar11 = *(int *)puVar14;
108: if (iVar11 != 0) {
109: if (0x20 < iVar11) {
110: *(undefined4 *)(*param_1 + 0x28) = 0x27;
111: (**(code **)*param_1)(param_1);
112: }
113: *(char *)((long)&uStack104 + (long)iVar11) =
114: *(char *)((long)&uStack104 + (long)iVar11) + '\x01';
115: }
116: puVar14 = (undefined8 *)((long)puVar14 + 4);
117: } while (puVar14 != (undefined8 *)aiStack1156);
118: puVar8 = (undefined8 *)&uStack72;
119: iVar11 = 0x1f;
120: do {
121: while (cVar9 = *(char *)puVar8, cVar9 != '\0') {
122: iVar11 = iVar11 + -1;
123: do {
124: cVar4 = *(char *)((long)puVar8 + -2);
125: iVar5 = iVar11;
126: lVar7 = (long)iVar11;
127: while (cVar4 == '\0') {
128: iVar5 = iVar5 + -1;
129: lVar7 = (long)iVar5;
130: cVar4 = *(char *)((long)&uStack104 + lVar7);
131: }
132: *(char *)((long)puVar8 + -1) = *(char *)((long)puVar8 + -1) + '\x01';
133: *(char *)puVar8 = cVar9 + -2;
134: pcVar3 = (char *)((long)&uStack104 + (long)(iVar5 + 1));
135: *pcVar3 = *pcVar3 + '\x02';
136: *(char *)((long)&uStack104 + lVar7) = *(char *)((long)&uStack104 + lVar7) + -1;
137: cVar9 = *(char *)puVar8;
138: } while (cVar9 != '\0');
139: puVar8 = (undefined8 *)((long)puVar8 + -1);
140: if (puVar8 == &uStack88) goto LAB_00112060;
141: }
142: puVar8 = (undefined8 *)((long)puVar8 + -1);
143: iVar11 = iVar11 + -1;
144: } while (puVar8 != &uStack88);
145: LAB_00112060:
146: lVar7 = 0x10;
147: if ((char)uStack88 == '\0') {
148: if (uStack96._7_1_ == '\0') {
149: if (uStack96._6_1_ == '\0') {
150: if (uStack96._5_1_ == '\0') {
151: if (uStack96._4_1_ == '\0') {
152: if (uStack96._3_1_ == '\0') {
153: if (uStack96._2_1_ == '\0') {
154: if (uStack96._1_1_ == '\0') {
155: if ((char)uStack96 == '\0') {
156: if (uStack104._7_1_ == '\0') {
157: if (uStack104._6_1_ == '\0') {
158: if (uStack104._5_1_ == '\0') {
159: if (uStack104._4_1_ == '\0') {
160: if (uStack104._3_1_ == '\0') {
161: if (uStack104._2_1_ == '\0') {
162: if (uStack104._1_1_ == '\0') {
163: lVar7 = 0;
164: uStack88._0_1_ = (char)uStack104;
165: }
166: else {
167: lVar7 = 1;
168: uStack88._0_1_ = uStack104._1_1_;
169: }
170: }
171: else {
172: lVar7 = 2;
173: uStack88._0_1_ = uStack104._2_1_;
174: }
175: }
176: else {
177: lVar7 = 3;
178: uStack88._0_1_ = uStack104._3_1_;
179: }
180: }
181: else {
182: lVar7 = 4;
183: uStack88._0_1_ = uStack104._4_1_;
184: }
185: }
186: else {
187: lVar7 = 5;
188: uStack88._0_1_ = uStack104._5_1_;
189: }
190: }
191: else {
192: lVar7 = 6;
193: uStack88._0_1_ = uStack104._6_1_;
194: }
195: }
196: else {
197: lVar7 = 7;
198: uStack88._0_1_ = uStack104._7_1_;
199: }
200: }
201: else {
202: lVar7 = 8;
203: uStack88._0_1_ = (char)uStack96;
204: }
205: }
206: else {
207: lVar7 = 9;
208: uStack88._0_1_ = uStack96._1_1_;
209: }
210: }
211: else {
212: lVar7 = 10;
213: uStack88._0_1_ = uStack96._2_1_;
214: }
215: }
216: else {
217: lVar7 = 0xb;
218: uStack88._0_1_ = uStack96._3_1_;
219: }
220: }
221: else {
222: lVar7 = 0xc;
223: uStack88._0_1_ = uStack96._4_1_;
224: }
225: }
226: else {
227: lVar7 = 0xd;
228: uStack88._0_1_ = uStack96._5_1_;
229: }
230: }
231: else {
232: lVar7 = 0xe;
233: uStack88._0_1_ = uStack96._6_1_;
234: }
235: }
236: else {
237: lVar7 = 0xf;
238: uStack88._0_1_ = uStack96._7_1_;
239: }
240: }
241: iVar11 = 0;
242: *(char *)((long)&uStack104 + lVar7) = (char)uStack88 + -1;
243: iVar5 = 1;
244: *param_2 = uStack104;
245: param_2[1] = uStack96;
246: *(char *)(param_2 + 2) = (char)uStack88;
247: do {
248: lVar7 = 0;
249: do {
250: while (*(int *)((long)auStack2184 + lVar7 * 4) != iVar5) {
251: lVar7 = lVar7 + 1;
252: if (lVar7 == 0x100) goto LAB_001121d7;
253: }
254: lVar10 = (long)iVar11;
255: iVar11 = iVar11 + 1;
256: *(char *)((long)param_2 + lVar10 + 0x11) = (char)lVar7;
257: lVar7 = lVar7 + 1;
258: } while (lVar7 != 0x100);
259: LAB_001121d7:
260: iVar5 = iVar5 + 1;
261: if (iVar5 == 0x21) {
262: lVar7 = *(long *)(in_FS_OFFSET + 0x28);
263: *(undefined4 *)((long)param_2 + 0x114) = 0;
264: if (lStack64 != lVar7) {
265: /* WARNING: Subroutine does not return */
266: __stack_chk_fail();
267: }
268: return;
269: }
270: } while( true );
271: }
272: 
