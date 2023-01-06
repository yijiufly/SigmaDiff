1: 
2: undefined8 FUN_00126d40(long param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: uint uVar5;
10: int iVar6;
11: int iVar7;
12: undefined8 uVar8;
13: long lVar9;
14: long lVar10;
15: long *plVar11;
16: long *plVar12;
17: long lVar13;
18: uint uVar14;
19: long lVar15;
20: long in_FS_OFFSET;
21: long lStack136;
22: long lStack128;
23: undefined8 uStack112;
24: long alStack104 [5];
25: long lStack64;
26: 
27: lVar3 = *(long *)(param_1 + 0x230);
28: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
29: if (0 < *(int *)(param_1 + 0x1b0)) {
30: lVar15 = 1;
31: do {
32: lVar4 = *(long *)(param_1 + 0x1b0 + lVar15 * 8);
33: uVar8 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
34: (param_1,*(undefined8 *)(lVar3 + 0x90 + (long)*(int *)(lVar4 + 4) * 8),
35: *(int *)(param_1 + 0xb0) * *(int *)(lVar4 + 0xc));
36: (&uStack112)[lVar15] = uVar8;
37: iVar7 = (int)lVar15;
38: lVar15 = lVar15 + 1;
39: } while (*(int *)(param_1 + 0x1b0) != iVar7 && iVar7 <= *(int *)(param_1 + 0x1b0));
40: }
41: uStack112._4_4_ = *(int *)(lVar3 + 0x2c);
42: lStack128 = (long)uStack112._4_4_;
43: iVar7 = *(int *)(lVar3 + 0x30);
44: if (uStack112._4_4_ < iVar7) {
45: lStack136 = lStack128 << 3;
46: uVar14 = *(uint *)(lVar3 + 0x28);
47: uVar5 = *(uint *)(param_1 + 0x1d8);
48: do {
49: if (uVar14 < uVar5) {
50: do {
51: iVar7 = *(int *)(param_1 + 0x1b0);
52: lVar15 = 0;
53: iVar6 = 0;
54: if (0 < iVar7) {
55: do {
56: while( true ) {
57: lVar4 = *(long *)(param_1 + 0x1b8 + lVar15 * 8);
58: iVar1 = *(int *)(lVar4 + 0x34);
59: iVar2 = *(int *)(lVar4 + 0x38);
60: if (0 < iVar2) break;
61: joined_r0x001271d9:
62: iVar1 = (int)lVar15;
63: lVar15 = lVar15 + 1;
64: if (iVar7 <= iVar1 + 1) goto LAB_00126f6d;
65: }
66: lVar13 = (ulong)(iVar1 * uVar14) * 0x80;
67: lVar4 = alStack104[lVar15];
68: if (iVar1 < 1) goto joined_r0x001271d9;
69: if (iVar1 != 9) {
70: if (iVar1 == 8) {
71: plVar11 = (long *)(lStack136 + lVar4);
72: do {
73: lVar10 = *plVar11;
74: plVar11 = plVar11 + 1;
75: lVar9 = lVar3 + (long)iVar6 * 8;
76: iVar6 = iVar6 + 8;
77: lVar10 = lVar10 + lVar13;
78: *(long *)(lVar9 + 0x38) = lVar10;
79: *(long *)(lVar9 + 0x40) = lVar10 + 0x80;
80: *(long *)(lVar9 + 0x48) = lVar10 + 0x100;
81: *(long *)(lVar9 + 0x50) = lVar10 + 0x180;
82: *(long *)(lVar9 + 0x58) = lVar10 + 0x200;
83: *(long *)(lVar9 + 0x60) = lVar10 + 0x280;
84: *(long *)(lVar9 + 0x70) = lVar10 + 0x380;
85: *(long *)(lVar9 + 0x68) = lVar10 + 0x300;
86: } while (plVar11 != (long *)(lVar4 + 8 + ((ulong)(iVar2 - 1) + lStack128) * 8));
87: }
88: else {
89: if (iVar1 == 7) {
90: plVar11 = (long *)(lStack136 + lVar4);
91: do {
92: lVar10 = *plVar11;
93: plVar11 = plVar11 + 1;
94: lVar9 = lVar3 + (long)iVar6 * 8;
95: iVar6 = iVar6 + 7;
96: lVar10 = lVar10 + lVar13;
97: *(long *)(lVar9 + 0x38) = lVar10;
98: *(long *)(lVar9 + 0x40) = lVar10 + 0x80;
99: *(long *)(lVar9 + 0x48) = lVar10 + 0x100;
100: *(long *)(lVar9 + 0x50) = lVar10 + 0x180;
101: *(long *)(lVar9 + 0x58) = lVar10 + 0x200;
102: *(long *)(lVar9 + 0x68) = lVar10 + 0x300;
103: *(long *)(lVar9 + 0x60) = lVar10 + 0x280;
104: } while (plVar11 != (long *)(lVar4 + 8 + ((ulong)(iVar2 - 1) + lStack128) * 8));
105: }
106: else {
107: plVar12 = (long *)(lStack136 + lVar4);
108: plVar11 = (long *)(lVar4 + 8 + ((ulong)(iVar2 - 1) + lStack128) * 8);
109: do {
110: while( true ) {
111: iVar2 = iVar6 + 1;
112: lVar4 = lVar3 + (long)iVar6 * 8;
113: lVar9 = *plVar12 + lVar13;
114: *(long *)(lVar4 + 0x38) = lVar9;
115: if (iVar1 != 1) break;
116: plVar12 = plVar12 + 1;
117: iVar6 = iVar2;
118: if (plVar12 == plVar11) goto joined_r0x001271d9;
119: }
120: *(long *)(lVar4 + 0x40) = lVar9 + 0x80;
121: iVar2 = iVar6 + 2;
122: if (iVar1 != 2) {
123: *(long *)(lVar4 + 0x48) = lVar9 + 0x100;
124: iVar2 = iVar6 + 3;
125: if (iVar1 != 3) {
126: *(long *)(lVar4 + 0x50) = lVar9 + 0x180;
127: iVar2 = iVar6 + 4;
128: if (iVar1 != 4) {
129: *(long *)(lVar4 + 0x58) = lVar9 + 0x200;
130: iVar2 = iVar6 + 5;
131: if (iVar1 != 5) {
132: *(long *)(lVar4 + 0x60) = lVar9 + 0x280;
133: iVar2 = iVar6 + 6;
134: if (iVar1 != 6) {
135: *(long *)(lVar4 + 0x68) = lVar9 + 0x300;
136: *(long *)(lVar4 + 0x70) = lVar9 + 0x380;
137: *(long *)(lVar4 + 0x80) = lVar9 + 0x480;
138: *(long *)(lVar4 + 0x78) = lVar9 + 0x400;
139: iVar2 = iVar6 + 10;
140: }
141: }
142: }
143: }
144: }
145: iVar6 = iVar2;
146: plVar12 = plVar12 + 1;
147: } while (plVar12 != plVar11);
148: }
149: }
150: goto joined_r0x001271d9;
151: }
152: plVar11 = (long *)(lStack136 + lVar4);
153: do {
154: lVar10 = *plVar11;
155: plVar11 = plVar11 + 1;
156: lVar9 = lVar3 + (long)iVar6 * 8;
157: iVar6 = iVar6 + 9;
158: lVar10 = lVar10 + lVar13;
159: *(long *)(lVar9 + 0x38) = lVar10;
160: *(long *)(lVar9 + 0x40) = lVar10 + 0x80;
161: *(long *)(lVar9 + 0x48) = lVar10 + 0x100;
162: *(long *)(lVar9 + 0x50) = lVar10 + 0x180;
163: *(long *)(lVar9 + 0x58) = lVar10 + 0x200;
164: *(long *)(lVar9 + 0x60) = lVar10 + 0x280;
165: *(long *)(lVar9 + 0x68) = lVar10 + 0x300;
166: *(long *)(lVar9 + 0x78) = lVar10 + 0x400;
167: *(long *)(lVar9 + 0x70) = lVar10 + 0x380;
168: } while (plVar11 != (long *)(lVar4 + 8 + ((ulong)(iVar2 - 1) + lStack128) * 8));
169: lVar15 = lVar15 + 1;
170: } while ((int)lVar15 < iVar7);
171: }
172: LAB_00126f6d:
173: lVar15 = *(long *)(param_1 + 0x250);
174: if (*(int *)(lVar15 + 0x10) == 0) {
175: *(undefined4 *)(*(long *)(param_1 + 0x220) + 0x70) = *(undefined4 *)(param_1 + 0xb0);
176: }
177: iVar7 = (**(code **)(lVar15 + 8))(param_1);
178: if (iVar7 == 0) {
179: *(uint *)(lVar3 + 0x28) = uVar14;
180: *(int *)(lVar3 + 0x2c) = uStack112._4_4_;
181: uVar8 = 0;
182: goto LAB_001271f1;
183: }
184: uVar5 = *(uint *)(param_1 + 0x1d8);
185: uVar14 = uVar14 + 1;
186: } while (uVar14 < uVar5);
187: iVar7 = *(int *)(lVar3 + 0x30);
188: }
189: uStack112._4_4_ = uStack112._4_4_ + 1;
190: lStack136 = lStack136 + 8;
191: uVar14 = 0;
192: *(undefined4 *)(lVar3 + 0x28) = 0;
193: lStack128 = lStack128 + 1;
194: } while (uStack112._4_4_ < iVar7);
195: }
196: uVar14 = *(int *)(param_1 + 0xb0) + 1;
197: *(uint *)(param_1 + 0xb0) = uVar14;
198: if (uVar14 < *(uint *)(param_1 + 0x1a4)) {
199: lVar3 = *(long *)(param_1 + 0x230);
200: if (*(int *)(param_1 + 0x1b0) < 2) {
201: if (uVar14 < *(uint *)(param_1 + 0x1a4) - 1) {
202: *(undefined4 *)(lVar3 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0xc);
203: }
204: else {
205: *(undefined4 *)(lVar3 + 0x30) = *(undefined4 *)(*(long *)(param_1 + 0x1b8) + 0x48);
206: }
207: }
208: else {
209: *(undefined4 *)(lVar3 + 0x30) = 1;
210: }
211: *(undefined8 *)(lVar3 + 0x28) = 0;
212: uVar8 = 3;
213: }
214: else {
215: (**(code **)(*(long *)(param_1 + 0x240) + 0x18))(param_1);
216: uVar8 = 4;
217: }
218: LAB_001271f1:
219: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
220: return uVar8;
221: }
222: /* WARNING: Subroutine does not return */
223: __stack_chk_fail();
224: }
225: 
