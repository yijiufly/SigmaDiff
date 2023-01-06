1: 
2: undefined8 FUN_00103350(long param_1)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: long lVar3;
8: uint uVar4;
9: int iVar5;
10: int iVar6;
11: undefined8 uVar7;
12: long lVar8;
13: long lVar9;
14: long *plVar10;
15: long *plVar11;
16: long lVar12;
17: uint uVar13;
18: long lVar14;
19: int iVar15;
20: long in_FS_OFFSET;
21: long lStack136;
22: long lStack128;
23: undefined8 uStack112;
24: long alStack104 [5];
25: long lStack64;
26: 
27: iVar15 = *(int *)(param_1 + 0x144);
28: lVar2 = *(long *)(param_1 + 0x1c8);
29: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
30: if (0 < iVar15) {
31: lVar14 = 1;
32: do {
33: lVar3 = *(long *)(param_1 + 0x140 + lVar14 * 8);
34: iVar15 = *(int *)(lVar3 + 0xc);
35: uVar7 = (**(code **)(*(long *)(param_1 + 8) + 0x40))
36: (param_1,*(undefined8 *)(lVar2 + 0x70 + (long)*(int *)(lVar3 + 4) * 8),
37: *(int *)(lVar2 + 0x10) * iVar15,iVar15);
38: iVar15 = *(int *)(param_1 + 0x144);
39: (&uStack112)[lVar14] = uVar7;
40: iVar5 = (int)lVar14;
41: lVar14 = lVar14 + 1;
42: } while (iVar5 < iVar15);
43: }
44: uStack112._4_4_ = *(int *)(lVar2 + 0x18);
45: lStack128 = (long)uStack112._4_4_;
46: iVar5 = *(int *)(lVar2 + 0x1c);
47: if (uStack112._4_4_ < iVar5) {
48: lStack136 = lStack128 << 3;
49: uVar13 = *(uint *)(lVar2 + 0x14);
50: uVar4 = *(uint *)(param_1 + 0x168);
51: do {
52: if (uVar13 < uVar4) {
53: do {
54: lVar14 = 0;
55: iVar5 = 0;
56: if (0 < iVar15) {
57: do {
58: while( true ) {
59: lVar3 = *(long *)(param_1 + 0x148 + lVar14 * 8);
60: iVar1 = *(int *)(lVar3 + 0x34);
61: iVar6 = *(int *)(lVar3 + 0x38);
62: if (0 < iVar6) break;
63: joined_r0x001037c9:
64: iVar1 = (int)lVar14;
65: lVar14 = lVar14 + 1;
66: if (iVar15 <= iVar1 + 1) goto LAB_0010356d;
67: }
68: lVar12 = (ulong)(iVar1 * uVar13) * 0x80;
69: lVar3 = alStack104[lVar14];
70: if (iVar1 < 1) goto joined_r0x001037c9;
71: if (iVar1 != 9) {
72: if (iVar1 == 8) {
73: plVar10 = (long *)(lStack136 + lVar3);
74: do {
75: lVar9 = *plVar10;
76: plVar10 = plVar10 + 1;
77: lVar8 = lVar2 + (long)iVar5 * 8;
78: iVar5 = iVar5 + 8;
79: lVar9 = lVar9 + lVar12;
80: *(long *)(lVar8 + 0x20) = lVar9;
81: *(long *)(lVar8 + 0x28) = lVar9 + 0x80;
82: *(long *)(lVar8 + 0x30) = lVar9 + 0x100;
83: *(long *)(lVar8 + 0x38) = lVar9 + 0x180;
84: *(long *)(lVar8 + 0x40) = lVar9 + 0x200;
85: *(long *)(lVar8 + 0x48) = lVar9 + 0x280;
86: *(long *)(lVar8 + 0x58) = lVar9 + 0x380;
87: *(long *)(lVar8 + 0x50) = lVar9 + 0x300;
88: } while (plVar10 != (long *)(lVar3 + 8 + ((ulong)(iVar6 - 1) + lStack128) * 8));
89: }
90: else {
91: if (iVar1 == 7) {
92: plVar10 = (long *)(lStack136 + lVar3);
93: do {
94: lVar9 = *plVar10;
95: plVar10 = plVar10 + 1;
96: lVar8 = lVar2 + (long)iVar5 * 8;
97: iVar5 = iVar5 + 7;
98: lVar9 = lVar9 + lVar12;
99: *(long *)(lVar8 + 0x20) = lVar9;
100: *(long *)(lVar8 + 0x28) = lVar9 + 0x80;
101: *(long *)(lVar8 + 0x30) = lVar9 + 0x100;
102: *(long *)(lVar8 + 0x38) = lVar9 + 0x180;
103: *(long *)(lVar8 + 0x40) = lVar9 + 0x200;
104: *(long *)(lVar8 + 0x50) = lVar9 + 0x300;
105: *(long *)(lVar8 + 0x48) = lVar9 + 0x280;
106: } while (plVar10 != (long *)(lVar3 + 8 + ((ulong)(iVar6 - 1) + lStack128) * 8));
107: }
108: else {
109: plVar11 = (long *)(lStack136 + lVar3);
110: plVar10 = (long *)(lVar3 + 8 + ((ulong)(iVar6 - 1) + lStack128) * 8);
111: iVar6 = iVar5;
112: do {
113: while( true ) {
114: iVar5 = iVar6 + 1;
115: lVar3 = lVar2 + (long)iVar6 * 8;
116: lVar8 = *plVar11 + lVar12;
117: *(long *)(lVar3 + 0x20) = lVar8;
118: if (iVar1 != 1) break;
119: plVar11 = plVar11 + 1;
120: iVar6 = iVar5;
121: if (plVar11 == plVar10) goto joined_r0x001037c9;
122: }
123: *(long *)(lVar3 + 0x28) = lVar8 + 0x80;
124: iVar5 = iVar6 + 2;
125: if (iVar1 != 2) {
126: *(long *)(lVar3 + 0x30) = lVar8 + 0x100;
127: iVar5 = iVar6 + 3;
128: if (iVar1 != 3) {
129: *(long *)(lVar3 + 0x38) = lVar8 + 0x180;
130: iVar5 = iVar6 + 4;
131: if (iVar1 != 4) {
132: *(long *)(lVar3 + 0x40) = lVar8 + 0x200;
133: iVar5 = iVar6 + 5;
134: if (iVar1 != 5) {
135: *(long *)(lVar3 + 0x48) = lVar8 + 0x280;
136: iVar5 = iVar6 + 6;
137: if (iVar1 != 6) {
138: *(long *)(lVar3 + 0x50) = lVar8 + 0x300;
139: *(long *)(lVar3 + 0x58) = lVar8 + 0x380;
140: *(long *)(lVar3 + 0x68) = lVar8 + 0x480;
141: *(long *)(lVar3 + 0x60) = lVar8 + 0x400;
142: iVar5 = iVar6 + 10;
143: }
144: }
145: }
146: }
147: }
148: iVar6 = iVar5;
149: plVar11 = plVar11 + 1;
150: iVar5 = iVar6;
151: } while (plVar11 != plVar10);
152: }
153: }
154: goto joined_r0x001037c9;
155: }
156: plVar10 = (long *)(lStack136 + lVar3);
157: do {
158: lVar9 = *plVar10;
159: plVar10 = plVar10 + 1;
160: lVar8 = lVar2 + (long)iVar5 * 8;
161: iVar5 = iVar5 + 9;
162: lVar9 = lVar9 + lVar12;
163: *(long *)(lVar8 + 0x20) = lVar9;
164: *(long *)(lVar8 + 0x28) = lVar9 + 0x80;
165: *(long *)(lVar8 + 0x30) = lVar9 + 0x100;
166: *(long *)(lVar8 + 0x38) = lVar9 + 0x180;
167: *(long *)(lVar8 + 0x40) = lVar9 + 0x200;
168: *(long *)(lVar8 + 0x48) = lVar9 + 0x280;
169: *(long *)(lVar8 + 0x50) = lVar9 + 0x300;
170: *(long *)(lVar8 + 0x60) = lVar9 + 0x400;
171: *(long *)(lVar8 + 0x58) = lVar9 + 0x380;
172: } while (plVar10 != (long *)(lVar3 + 8 + ((ulong)(iVar6 - 1) + lStack128) * 8));
173: lVar14 = lVar14 + 1;
174: } while ((int)lVar14 < iVar15);
175: }
176: LAB_0010356d:
177: uVar7 = (**(code **)(*(long *)(param_1 + 0x1f0) + 8))(param_1);
178: if ((int)uVar7 == 0) {
179: *(uint *)(lVar2 + 0x14) = uVar13;
180: *(int *)(lVar2 + 0x18) = uStack112._4_4_;
181: goto LAB_001037df;
182: }
183: uVar4 = *(uint *)(param_1 + 0x168);
184: uVar13 = uVar13 + 1;
185: iVar15 = *(int *)(param_1 + 0x144);
186: } while (uVar13 < uVar4);
187: iVar5 = *(int *)(lVar2 + 0x1c);
188: }
189: uStack112._4_4_ = uStack112._4_4_ + 1;
190: lStack136 = lStack136 + 8;
191: uVar13 = 0;
192: *(undefined4 *)(lVar2 + 0x14) = 0;
193: lStack128 = lStack128 + 1;
194: } while (uStack112._4_4_ < iVar5);
195: }
196: *(int *)(lVar2 + 0x10) = *(int *)(lVar2 + 0x10) + 1;
197: lVar2 = *(long *)(param_1 + 0x1c8);
198: if (*(int *)(param_1 + 0x144) < 2) {
199: if (*(uint *)(lVar2 + 0x10) < *(int *)(param_1 + 0x140) - 1U) {
200: *(undefined4 *)(lVar2 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0xc);
201: }
202: else {
203: *(undefined4 *)(lVar2 + 0x1c) = *(undefined4 *)(*(long *)(param_1 + 0x148) + 0x48);
204: }
205: }
206: else {
207: *(undefined4 *)(lVar2 + 0x1c) = 1;
208: }
209: *(undefined8 *)(lVar2 + 0x14) = 0;
210: uVar7 = 1;
211: LAB_001037df:
212: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
213: return uVar7;
214: }
215: /* WARNING: Subroutine does not return */
216: __stack_chk_fail();
217: }
218: 
