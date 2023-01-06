1: 
2: void FUN_0013d980(code **param_1,int param_2)
3: 
4: {
5: undefined4 uVar1;
6: code *pcVar2;
7: bool bVar3;
8: ulong uVar4;
9: code *pcVar5;
10: int iVar6;
11: uint uVar7;
12: code *pcVar8;
13: ulong uVar9;
14: undefined8 *puVar10;
15: undefined8 *puVar11;
16: code *pcVar12;
17: int iVar13;
18: code **ppcVar14;
19: code **ppcVar15;
20: bool bVar16;
21: byte bVar17;
22: 
23: bVar17 = 0;
24: pcVar2 = param_1[0x3e];
25: if (param_2 != 0) {
26: ppcVar14 = (code **)*param_1;
27: *(undefined4 *)(ppcVar14 + 5) = 0x30;
28: (**ppcVar14)();
29: }
30: iVar6 = *(int *)((long)param_1 + 0x134);
31: if (iVar6 == 0) {
32: *(code **)(pcVar2 + 8) = FUN_0013f200;
33: }
34: else {
35: if (*(int *)((long)param_1 + 0x1a4) == 0) {
36: pcVar8 = FUN_0013fd50;
37: if (*(int *)((long)param_1 + 0x19c) != 0) {
38: pcVar8 = FUN_0013fa10;
39: }
40: *(code **)(pcVar2 + 8) = pcVar8;
41: iVar13 = *(int *)((long)param_1 + 0x144);
42: goto joined_r0x0013da4b;
43: }
44: pcVar8 = FUN_0013f950;
45: if (*(int *)((long)param_1 + 0x19c) != 0) {
46: pcVar8 = FUN_0013f6e0;
47: }
48: *(code **)(pcVar2 + 8) = pcVar8;
49: }
50: iVar13 = *(int *)((long)param_1 + 0x144);
51: joined_r0x0013da4b:
52: if (iVar13 < 1) {
53: LAB_0013d9e8:
54: uVar1 = *(undefined4 *)(param_1 + 0x23);
55: *(undefined8 *)(pcVar2 + 0x18) = 0;
56: *(undefined8 *)(pcVar2 + 0x20) = 0x10000;
57: *(undefined8 *)(pcVar2 + 0x28) = 0;
58: *(undefined8 *)(pcVar2 + 0x30) = 0;
59: *(undefined4 *)(pcVar2 + 0x38) = 0xb;
60: *(undefined4 *)(pcVar2 + 0x3c) = 0xffffffff;
61: *(undefined4 *)(pcVar2 + 0x60) = uVar1;
62: *(undefined4 *)(pcVar2 + 100) = 0;
63: return;
64: }
65: iVar13 = 0;
66: pcVar8 = param_1[0x29];
67: pcVar12 = pcVar2;
68: ppcVar14 = param_1;
69: if (iVar6 == 0) goto LAB_0013db35;
70: LAB_0013da68:
71: if ((*(int *)((long)param_1 + 0x19c) == 0) && (*(int *)((long)param_1 + 0x1a4) == 0))
72: goto LAB_0013db35;
73: LAB_0013da82:
74: ppcVar15 = ppcVar14;
75: if (*(int *)(param_1 + 0x34) == 0) goto LAB_0013db07;
76: uVar7 = *(uint *)(pcVar8 + 0x18);
77: do {
78: if (0xf < uVar7) {
79: pcVar8 = *param_1;
80: *(uint *)(pcVar8 + 0x2c) = uVar7;
81: *(undefined4 *)(pcVar8 + 0x28) = 0x7d;
82: (**(code **)*param_1)(param_1);
83: }
84: puVar11 = *(undefined8 **)(pcVar2 + (long)(int)uVar7 * 8 + 0xe8);
85: if (puVar11 == (undefined8 *)0x0) {
86: puVar11 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x100);
87: *(undefined8 **)(pcVar2 + (long)(int)uVar7 * 8 + 0xe8) = puVar11;
88: }
89: bVar16 = ((ulong)puVar11 & 1) != 0;
90: uVar9 = 0x100;
91: if (bVar16) {
92: *(undefined *)puVar11 = 0;
93: puVar11 = (undefined8 *)((long)puVar11 + 1);
94: uVar9 = 0xff;
95: }
96: puVar10 = puVar11;
97: if (((ulong)puVar11 & 2) != 0) {
98: puVar10 = (undefined8 *)((long)puVar11 + 2);
99: uVar9 = (ulong)((int)uVar9 - 2);
100: *(undefined2 *)puVar11 = 0;
101: }
102: if (((ulong)puVar10 & 4) != 0) {
103: *(undefined4 *)puVar10 = 0;
104: uVar9 = (ulong)((int)uVar9 - 4);
105: puVar10 = (undefined8 *)((long)puVar10 + 4);
106: }
107: uVar4 = uVar9 >> 3;
108: while (uVar4 != 0) {
109: uVar4 = uVar4 - 1;
110: *puVar10 = 0;
111: puVar10 = puVar10 + (ulong)bVar17 * -2 + 1;
112: }
113: if ((uVar9 & 4) != 0) {
114: *(undefined4 *)puVar10 = 0;
115: puVar10 = (undefined8 *)((long)puVar10 + 4);
116: }
117: puVar11 = puVar10;
118: if ((uVar9 & 2) != 0) {
119: puVar11 = (undefined8 *)((long)puVar10 + 2);
120: *(undefined2 *)puVar10 = 0;
121: }
122: if (bVar16) {
123: *(undefined *)puVar11 = 0;
124: }
125: LAB_0013db07:
126: iVar13 = iVar13 + 1;
127: ppcVar14 = ppcVar15 + 1;
128: pcVar12 = pcVar12 + 4;
129: if (*(int *)((long)param_1 + 0x144) == iVar13 || *(int *)((long)param_1 + 0x144) < iVar13)
130: goto LAB_0013d9e8;
131: pcVar8 = ppcVar15[0x2a];
132: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0013da68;
133: LAB_0013db35:
134: uVar7 = *(uint *)(pcVar8 + 0x14);
135: if (uVar7 < 0x10) {
136: pcVar5 = pcVar2 + (long)(int)uVar7 * 8;
137: puVar11 = *(undefined8 **)(pcVar5 + 0x68);
138: if (puVar11 != (undefined8 *)0x0) goto LAB_0013db54;
139: LAB_0013dc33:
140: puVar11 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x40);
141: *(undefined8 **)(pcVar5 + 0x68) = puVar11;
142: puVar10 = puVar11;
143: if (((ulong)puVar11 & 1) != 0) goto LAB_0013dc70;
144: LAB_0013db64:
145: uVar9 = 0x40;
146: bVar3 = false;
147: iVar6 = 0x40;
148: bVar16 = false;
149: if (((ulong)puVar10 & 2) == 0) goto LAB_0013db6e;
150: LAB_0013dc88:
151: puVar11 = (undefined8 *)((long)puVar10 + 2);
152: uVar7 = iVar6 - 2;
153: uVar9 = (ulong)uVar7;
154: *(undefined2 *)puVar10 = 0;
155: }
156: else {
157: *(undefined4 *)(*param_1 + 0x28) = 0x7d;
158: *(uint *)(*param_1 + 0x2c) = uVar7;
159: (**(code **)*param_1)(param_1);
160: pcVar5 = pcVar2 + (long)(int)uVar7 * 8;
161: puVar11 = *(undefined8 **)(pcVar5 + 0x68);
162: if (puVar11 == (undefined8 *)0x0) goto LAB_0013dc33;
163: LAB_0013db54:
164: puVar10 = puVar11;
165: if (((ulong)puVar11 & 1) == 0) goto LAB_0013db64;
166: LAB_0013dc70:
167: puVar10 = (undefined8 *)((long)puVar11 + 1);
168: *(undefined *)puVar11 = 0;
169: uVar9 = 0x3f;
170: bVar3 = true;
171: iVar6 = 0x3f;
172: bVar16 = true;
173: if (((ulong)puVar10 & 2) != 0) goto LAB_0013dc88;
174: LAB_0013db6e:
175: uVar7 = (uint)uVar9;
176: puVar11 = puVar10;
177: bVar16 = bVar3;
178: }
179: if (((ulong)puVar11 & 4) != 0) {
180: *(undefined4 *)puVar11 = 0;
181: uVar9 = (ulong)(uVar7 - 4);
182: puVar11 = (undefined8 *)((long)puVar11 + 4);
183: }
184: uVar4 = uVar9 >> 3;
185: while (uVar4 != 0) {
186: uVar4 = uVar4 - 1;
187: *puVar11 = 0;
188: puVar11 = puVar11 + (ulong)bVar17 * -2 + 1;
189: }
190: if ((uVar9 & 4) != 0) {
191: *(undefined4 *)puVar11 = 0;
192: puVar11 = (undefined8 *)((long)puVar11 + 4);
193: }
194: puVar10 = puVar11;
195: if ((uVar9 & 2) != 0) {
196: puVar10 = (undefined8 *)((long)puVar11 + 2);
197: *(undefined2 *)puVar11 = 0;
198: }
199: if (bVar16) {
200: *(undefined *)puVar10 = 0;
201: }
202: *(undefined4 *)(pcVar12 + 0x40) = 0;
203: *(undefined4 *)(pcVar12 + 0x50) = 0;
204: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0013da82;
205: uVar7 = *(uint *)(pcVar8 + 0x18);
206: ppcVar15 = ppcVar14;
207: } while( true );
208: }
209: 
