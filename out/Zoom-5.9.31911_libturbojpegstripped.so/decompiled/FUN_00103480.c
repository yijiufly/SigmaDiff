1: 
2: undefined8 FUN_00103480(long param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: uint uStack108;
18: int iStack100;
19: long alStack88 [5];
20: 
21: lVar12 = 0;
22: lVar3 = *(long *)(param_1 + 0x1c8);
23: if (0 < *(int *)(param_1 + 0x144)) {
24: do {
25: lVar8 = *(long *)(param_1 + 0x148 + lVar12 * 8);
26: iVar6 = *(int *)(lVar8 + 0xc);
27: lVar8 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
28: (param_1,*(undefined8 *)(lVar3 + 0x70 + (long)*(int *)(lVar8 + 4) * 8),
29: *(int *)(lVar3 + 0x10) * iVar6,iVar6,0);
30: alStack88[lVar12] = lVar8;
31: iVar6 = (int)lVar12 + 1;
32: lVar12 = lVar12 + 1;
33: } while (*(int *)(param_1 + 0x144) != iVar6 && iVar6 <= *(int *)(param_1 + 0x144));
34: }
35: iStack100 = *(int *)(lVar3 + 0x18);
36: iVar6 = *(int *)(lVar3 + 0x1c);
37: if (iStack100 < iVar6) {
38: uStack108 = *(uint *)(lVar3 + 0x14);
39: lVar12 = (long)iStack100 * 8;
40: do {
41: if (uStack108 <= *(uint *)(param_1 + 0x168) && *(uint *)(param_1 + 0x168) != uStack108) {
42: do {
43: iVar6 = *(int *)(param_1 + 0x144);
44: if (0 < iVar6) {
45: lVar8 = 0;
46: iVar7 = 0;
47: do {
48: while( true ) {
49: lVar4 = *(long *)(param_1 + 0x148 + lVar8 * 8);
50: iVar1 = *(int *)(lVar4 + 0x34);
51: iVar2 = *(int *)(lVar4 + 0x38);
52: if (0 < iVar2) break;
53: joined_r0x00103a15:
54: iVar1 = (int)lVar8;
55: lVar8 = lVar8 + 1;
56: if (iVar6 <= iVar1 + 1) goto LAB_001036c7;
57: }
58: lVar11 = (ulong)(uStack108 * iVar1) * 0x80;
59: lVar4 = alStack88[lVar8];
60: if (iVar1 < 1) goto joined_r0x00103a15;
61: if (iVar1 != 1) {
62: if (iVar1 == 2) {
63: lVar9 = lVar11 + *(long *)(lVar4 + lVar12);
64: *(long *)(lVar3 + 0x20 + (long)iVar7 * 8) = lVar9;
65: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 1) * 8) = lVar9 + 0x80;
66: if (iVar2 != 1) {
67: lVar9 = lVar11 + *(long *)(lVar4 + 8 + lVar12);
68: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 2) * 8) = lVar9;
69: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 3) * 8) = lVar9 + 0x80;
70: if (iVar2 != 2) {
71: lVar9 = lVar11 + *(long *)(lVar4 + 0x10 + lVar12);
72: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 4) * 8) = lVar9;
73: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 5) * 8) = lVar9 + 0x80;
74: if (iVar2 != 3) {
75: lVar9 = lVar11 + *(long *)(lVar4 + 0x18 + lVar12);
76: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 6) * 8) = lVar9;
77: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 7) * 8) = lVar9 + 0x80;
78: if (iVar2 != 4) {
79: lVar11 = lVar11 + *(long *)(lVar4 + 0x20 + lVar12);
80: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 8) * 8) = lVar11;
81: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 9) * 8) = lVar11 + 0x80;
82: }
83: }
84: }
85: }
86: iVar7 = iVar7 + iVar2 * 2;
87: }
88: else {
89: lVar9 = 0;
90: if (iVar1 == 3) {
91: lVar9 = lVar11 + *(long *)(lVar4 + lVar12);
92: *(long *)(lVar3 + 0x20 + (long)iVar7 * 8) = lVar9;
93: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 1) * 8) = lVar9 + 0x80;
94: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 2) * 8) = lVar9 + 0x100;
95: if (iVar2 != 1) {
96: lVar9 = lVar11 + *(long *)(lVar4 + 8 + lVar12);
97: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 3) * 8) = lVar9;
98: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 4) * 8) = lVar9 + 0x80;
99: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 5) * 8) = lVar9 + 0x100;
100: if (iVar2 != 2) {
101: lVar9 = lVar11 + *(long *)(lVar4 + 0x10 + lVar12);
102: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 6) * 8) = lVar9;
103: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 7) * 8) = lVar9 + 0x80;
104: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 8) * 8) = lVar9 + 0x100;
105: if (iVar2 != 3) {
106: lVar11 = lVar11 + *(long *)(lVar4 + 0x18 + lVar12);
107: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 9) * 8) = lVar11;
108: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 10) * 8) = lVar11 + 0x80;
109: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 0xb) * 8) = lVar11 + 0x100;
110: }
111: }
112: }
113: iVar7 = iVar7 + iVar2 * 3;
114: }
115: else {
116: do {
117: while( true ) {
118: lVar10 = lVar11 + *(long *)(lVar4 + lVar12 + lVar9 * 8);
119: *(long *)(lVar3 + 0x20 + (long)iVar7 * 8) = lVar10;
120: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 1) * 8) = lVar10 + 0x80;
121: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 2) * 8) = lVar10 + 0x100;
122: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 3) * 8) = lVar10 + 0x180;
123: iVar5 = iVar7 + 4;
124: if (iVar1 != 4) break;
125: LAB_001036a7:
126: iVar7 = iVar5;
127: lVar9 = lVar9 + 1;
128: if (iVar2 <= (int)lVar9) goto joined_r0x00103a15;
129: }
130: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 4) * 8) = lVar10 + 0x200;
131: iVar5 = iVar7 + 5;
132: if (iVar1 != 5) {
133: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 5) * 8) = lVar10 + 0x280;
134: iVar5 = iVar7 + 6;
135: if (iVar1 == 6) goto LAB_001036a7;
136: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 6) * 8) = lVar10 + 0x300;
137: iVar5 = iVar7 + 7;
138: if (iVar1 != 7) {
139: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 7) * 8) = lVar10 + 0x380;
140: iVar5 = iVar7 + 8;
141: if (iVar1 == 8) goto LAB_001036a7;
142: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 8) * 8) = lVar10 + 0x400;
143: iVar5 = iVar7 + 9;
144: if (iVar1 != 9) {
145: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 9) * 8) = lVar10 + 0x480;
146: iVar5 = iVar7 + 10;
147: }
148: }
149: }
150: iVar7 = iVar5;
151: lVar9 = lVar9 + 1;
152: } while ((int)lVar9 < iVar2);
153: }
154: }
155: goto joined_r0x00103a15;
156: }
157: *(long *)(lVar3 + 0x20 + (long)iVar7 * 8) = lVar11 + *(long *)(lVar4 + lVar12);
158: if (iVar2 != 1) {
159: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 1) * 8) =
160: lVar11 + *(long *)(lVar4 + 8 + lVar12);
161: if (iVar2 != 2) {
162: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 2) * 8) =
163: lVar11 + *(long *)(lVar4 + 0x10 + lVar12);
164: if (iVar2 != 3) {
165: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 3) * 8) =
166: lVar11 + *(long *)(lVar4 + 0x18 + lVar12);
167: if (iVar2 != 4) {
168: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 4) * 8) =
169: lVar11 + *(long *)(lVar4 + 0x20 + lVar12);
170: if (iVar2 != 5) {
171: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 5) * 8) =
172: lVar11 + *(long *)(lVar4 + 0x28 + lVar12);
173: if (iVar2 != 6) {
174: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 6) * 8) =
175: lVar11 + *(long *)(lVar4 + 0x30 + lVar12);
176: if (iVar2 != 7) {
177: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 7) * 8) =
178: lVar11 + *(long *)(lVar4 + 0x38 + lVar12);
179: if (iVar2 != 8) {
180: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 8) * 8) =
181: lVar11 + *(long *)(lVar4 + 0x40 + lVar12);
182: if (iVar2 != 9) {
183: *(long *)(lVar3 + 0x20 + (long)(iVar7 + 9) * 8) =
184: lVar11 + *(long *)(lVar4 + 0x48 + lVar12);
185: }
186: }
187: }
188: }
189: }
190: }
191: }
192: }
193: }
194: iVar7 = iVar7 + iVar2;
195: lVar8 = lVar8 + 1;
196: } while ((int)lVar8 < iVar6);
197: }
198: LAB_001036c7:
199: iVar6 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))();
200: if (iVar6 == 0) {
201: *(int *)(lVar3 + 0x18) = iStack100;
202: *(uint *)(lVar3 + 0x14) = uStack108;
203: return 0;
204: }
205: uStack108 = uStack108 + 1;
206: } while (uStack108 <= *(uint *)(param_1 + 0x168) && *(uint *)(param_1 + 0x168) != uStack108)
207: ;
208: iVar6 = *(int *)(lVar3 + 0x1c);
209: }
210: iStack100 = iStack100 + 1;
211: lVar12 = lVar12 + 8;
212: *(undefined4 *)(lVar3 + 0x14) = 0;
213: if (iVar6 <= iStack100) break;
214: uStack108 = 0;
215: } while( true );
216: }
217: *(int *)(lVar3 + 0x10) = *(int *)(lVar3 + 0x10) + 1;
218: FUN_00103400(param_1);
219: return 1;
220: }
221: 
