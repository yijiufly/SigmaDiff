1: 
2: void FUN_0014ca40(code **param_1)
3: 
4: {
5: int iVar1;
6: uint uVar2;
7: undefined4 uVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: code *pcVar6;
11: code *pcVar7;
12: long lVar8;
13: undefined (*pauVar9) [16];
14: undefined8 *puVar10;
15: int iVar11;
16: ulong uVar12;
17: long lVar13;
18: int *piVar14;
19: int iVar15;
20: int iVar16;
21: byte bVar17;
22: long lStack80;
23: 
24: bVar17 = 0;
25: pcVar4 = param_1[0x4a];
26: iVar16 = *(int *)((long)param_1 + 0x20c);
27: if (*(int *)(param_1 + 0x27) == 0) {
28: if ((((iVar16 != 0) || (*(int *)((long)param_1 + 0x214) != 0)) ||
29: (*(int *)(param_1 + 0x43) != 0)) || (*(int *)(param_1 + 0x42) < 0x3f)) {
30: pcVar6 = *param_1;
31: *(undefined4 *)(pcVar6 + 0x28) = 0x7a;
32: (**(code **)(pcVar6 + 8))();
33: }
34: *(code **)(pcVar4 + 8) = FUN_0014d5b0;
35: goto LAB_0014cbd9;
36: }
37: iVar11 = *(int *)(param_1 + 0x42);
38: iVar1 = *(int *)((long)param_1 + 0x214);
39: iVar15 = *(int *)(param_1 + 0x43);
40: if (iVar16 == 0) {
41: if (iVar11 != 0) goto LAB_0014ca90;
42: LAB_0014cd80:
43: if (((iVar1 != 0) && (iVar1 + -1 != iVar15)) || (0xd < iVar15)) goto LAB_0014ca90;
44: }
45: else {
46: if (((iVar11 < 0x40) && (iVar16 <= iVar11)) && (*(int *)(param_1 + 0x36) == 1))
47: goto LAB_0014cd80;
48: LAB_0014ca90:
49: ppcVar5 = (code **)*param_1;
50: *(int *)((long)ppcVar5 + 0x2c) = iVar16;
51: *(int *)(ppcVar5 + 7) = iVar15;
52: *(undefined4 *)(ppcVar5 + 5) = 0x10;
53: *(int *)(ppcVar5 + 6) = iVar11;
54: *(int *)((long)ppcVar5 + 0x34) = iVar1;
55: (**ppcVar5)();
56: iVar16 = *(int *)((long)param_1 + 0x20c);
57: }
58: if (0 < *(int *)(param_1 + 0x36)) {
59: lStack80 = 1;
60: do {
61: iVar11 = *(int *)(param_1 + 7);
62: pcVar6 = param_1[0x18];
63: iVar1 = *(int *)(param_1[lStack80 + 0x36] + 4);
64: piVar14 = (int *)(pcVar6 + (long)iVar1 * 0x100);
65: if (iVar16 != 0) {
66: if (*piVar14 < 0) {
67: pcVar7 = *param_1;
68: *(undefined4 *)(pcVar7 + 0x28) = 0x73;
69: *(int *)(pcVar7 + 0x2c) = iVar1;
70: *(undefined4 *)(pcVar7 + 0x30) = 0;
71: (**(code **)(pcVar7 + 8))(param_1,0xffffffff);
72: iVar16 = *(int *)((long)param_1 + 0x20c);
73: }
74: if (0 < iVar16) {
75: iVar16 = 1;
76: }
77: }
78: lVar13 = (long)(iVar16 + 1);
79: lVar8 = iVar16 - lVar13;
80: pcVar6 = pcVar6 + lVar8 * 4 + (long)(iVar11 + iVar1) * 0x100;
81: do {
82: if (*(int *)((long)param_1 + 0xac) < 2) {
83: *(undefined4 *)(pcVar6 + lVar13 * 4) = 0;
84: }
85: else {
86: *(int *)(pcVar6 + lVar13 * 4) = piVar14[lVar8 + lVar13];
87: }
88: iVar11 = *(int *)(param_1 + 0x42);
89: iVar16 = (int)lVar13;
90: lVar13 = lVar13 + 1;
91: iVar15 = 9;
92: if (8 < iVar11) {
93: iVar15 = iVar11;
94: }
95: } while (iVar16 <= iVar15);
96: iVar16 = *(int *)((long)param_1 + 0x20c);
97: if (iVar16 <= iVar11) {
98: piVar14 = piVar14 + iVar16;
99: do {
100: iVar11 = 0;
101: if (-1 < *piVar14) {
102: iVar11 = *piVar14;
103: }
104: if (*(int *)((long)param_1 + 0x214) != iVar11) {
105: pcVar6 = *param_1;
106: *(undefined4 *)(pcVar6 + 0x28) = 0x73;
107: *(int *)(pcVar6 + 0x2c) = iVar1;
108: *(int *)(pcVar6 + 0x30) = iVar16;
109: (**(code **)(pcVar6 + 8))();
110: }
111: iVar16 = iVar16 + 1;
112: *piVar14 = *(int *)(param_1 + 0x43);
113: piVar14 = piVar14 + 1;
114: } while (iVar16 <= *(int *)(param_1 + 0x42));
115: iVar16 = *(int *)((long)param_1 + 0x20c);
116: }
117: iVar11 = (int)lStack80;
118: lStack80 = lStack80 + 1;
119: } while (*(int *)(param_1 + 0x36) != iVar11 && iVar11 <= *(int *)(param_1 + 0x36));
120: }
121: if (*(int *)((long)param_1 + 0x214) == 0) {
122: if (iVar16 == 0) {
123: *(code **)(pcVar4 + 8) = FUN_0014d120;
124: }
125: else {
126: *(code **)(pcVar4 + 8) = FUN_0014d380;
127: }
128: }
129: else {
130: if (iVar16 == 0) {
131: *(code **)(pcVar4 + 8) = FUN_0014de30;
132: }
133: else {
134: *(code **)(pcVar4 + 8) = FUN_0014d990;
135: }
136: }
137: LAB_0014cbd9:
138: if (0 < *(int *)(param_1 + 0x36)) {
139: lVar8 = 1;
140: do {
141: pcVar6 = param_1[lVar8 + 0x36];
142: if (*(int *)(param_1 + 0x27) == 0) {
143: LAB_0014cc22:
144: uVar2 = *(uint *)(pcVar6 + 0x14);
145: if (0xf < uVar2) {
146: ppcVar5 = (code **)*param_1;
147: *(undefined4 *)(ppcVar5 + 5) = 0x7d;
148: *(uint *)((long)ppcVar5 + 0x2c) = uVar2;
149: (**ppcVar5)();
150: }
151: pauVar9 = *(undefined (**) [16])(pcVar4 + (long)(int)uVar2 * 8 + 0x50);
152: if (pauVar9 == (undefined (*) [16])0x0) {
153: pauVar9 = (undefined (*) [16])(**(code **)param_1[1])(param_1,1,0x40);
154: *(undefined (**) [16])(pcVar4 + (long)(int)uVar2 * 8 + 0x50) = pauVar9;
155: }
156: *pauVar9 = (undefined  [16])0x0;
157: pauVar9[1] = (undefined  [16])0x0;
158: pauVar9[2] = (undefined  [16])0x0;
159: pauVar9[3] = (undefined  [16])0x0;
160: *(undefined4 *)(pcVar4 + lVar8 * 4 + 0x28) = 0;
161: *(undefined4 *)(pcVar4 + lVar8 * 4 + 0x38) = 0;
162: if ((*(int *)(param_1 + 0x27) == 0) || (*(int *)((long)param_1 + 0x20c) != 0)) {
163: LAB_0014cc97:
164: uVar2 = *(uint *)(pcVar6 + 0x18);
165: if (0xf < uVar2) {
166: ppcVar5 = (code **)*param_1;
167: *(undefined4 *)(ppcVar5 + 5) = 0x7d;
168: *(uint *)((long)ppcVar5 + 0x2c) = uVar2;
169: (**ppcVar5)(param_1);
170: }
171: puVar10 = *(undefined8 **)(pcVar4 + (long)(int)uVar2 * 8 + 0xd0);
172: if (puVar10 == (undefined8 *)0x0) {
173: puVar10 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x100);
174: *(undefined8 **)(pcVar4 + (long)(int)uVar2 * 8 + 0xd0) = puVar10;
175: }
176: *puVar10 = 0;
177: puVar10[0x1f] = 0;
178: uVar12 = (ulong)(((int)puVar10 -
179: (int)(undefined8 *)((ulong)(puVar10 + 1) & 0xfffffffffffffff8)) + 0x100U
180: >> 3);
181: puVar10 = (undefined8 *)((ulong)(puVar10 + 1) & 0xfffffffffffffff8);
182: while (uVar12 != 0) {
183: uVar12 = uVar12 - 1;
184: *puVar10 = 0;
185: puVar10 = puVar10 + (ulong)bVar17 * -2 + 1;
186: }
187: }
188: }
189: else {
190: if (*(int *)((long)param_1 + 0x20c) != 0) goto LAB_0014cc97;
191: if (*(int *)((long)param_1 + 0x214) == 0) goto LAB_0014cc22;
192: }
193: iVar16 = (int)lVar8;
194: lVar8 = lVar8 + 1;
195: } while (*(int *)(param_1 + 0x36) != iVar16 && iVar16 <= *(int *)(param_1 + 0x36));
196: }
197: uVar3 = *(undefined4 *)(param_1 + 0x2e);
198: *(undefined8 *)(pcVar4 + 0x18) = 0;
199: *(undefined8 *)(pcVar4 + 0x20) = 0;
200: *(undefined4 *)(pcVar4 + 0x28) = 0xfffffff0;
201: *(undefined4 *)(pcVar4 + 0x10) = 0;
202: *(undefined4 *)(pcVar4 + 0x4c) = uVar3;
203: return;
204: }
205: 
