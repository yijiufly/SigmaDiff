1: 
2: void FUN_00139c30(code **param_1)
3: 
4: {
5: int iVar1;
6: undefined4 uVar2;
7: code *pcVar3;
8: code *pcVar4;
9: bool bVar5;
10: bool bVar6;
11: int iVar7;
12: code **ppcVar8;
13: ulong uVar9;
14: undefined8 uVar10;
15: int iVar11;
16: uint uVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: code *pcVar17;
22: int iVar18;
23: long lVar19;
24: long lVar20;
25: int iVar21;
26: int iVar22;
27: int aiStack72 [6];
28: 
29: ppcVar8 = (code **)(**(code **)param_1[1])(param_1,1,0x98);
30: param_1[0x4e] = (code *)ppcVar8;
31: iVar21 = *(int *)(param_1 + 0x12);
32: ppcVar8[0xe] = (code *)0x0;
33: ppcVar8[10] = (code *)0x0;
34: *ppcVar8 = FUN_001395a0;
35: ppcVar8[2] = FUN_00139580;
36: ppcVar8[3] = FUN_00139590;
37: if (4 < iVar21) {
38: pcVar17 = *param_1;
39: *(undefined4 *)(pcVar17 + 0x28) = 0x37;
40: *(undefined4 *)(pcVar17 + 0x2c) = 4;
41: (**(code **)*param_1)();
42: }
43: iVar21 = *(int *)(param_1 + 0xf);
44: if (0x100 < iVar21) {
45: pcVar17 = *param_1;
46: *(undefined4 *)(pcVar17 + 0x28) = 0x39;
47: *(undefined4 *)(pcVar17 + 0x2c) = 0x100;
48: (**(code **)*param_1)();
49: iVar21 = *(int *)(param_1 + 0xf);
50: }
51: lVar20 = (long)iVar21;
52: pcVar3 = param_1[0x4e];
53: iVar21 = *(int *)(param_1 + 0x12);
54: lVar13 = 2;
55: pcVar17 = pcVar3 + 0x3c;
56: uVar9 = (ulong)*(uint *)(param_1 + 8);
57: aiStack72[0] = *(int *)(&DAT_0018b260 + uVar9 * 4);
58: aiStack72[1] = *(undefined4 *)(&DAT_0018b2c0 + uVar9 * 4);
59: aiStack72[2] = *(undefined4 *)(&DAT_0018b200 + uVar9 * 4);
60: iVar7 = 1;
61: do {
62: iVar11 = iVar7;
63: lVar14 = lVar13;
64: if (1 < iVar21) {
65: iVar7 = 1;
66: do {
67: iVar7 = iVar7 + 1;
68: lVar14 = lVar14 * lVar13;
69: } while (iVar7 != iVar21);
70: }
71: lVar13 = lVar13 + 1;
72: iVar7 = iVar11 + 1;
73: } while (lVar14 <= lVar20);
74: if (iVar11 == 1) {
75: pcVar4 = *param_1;
76: *(undefined4 *)(pcVar4 + 0x28) = 0x38;
77: *(int *)(pcVar4 + 0x2c) = (int)lVar14;
78: (**(code **)*param_1)();
79: }
80: if (iVar21 < 1) {
81: iVar7 = 1;
82: }
83: else {
84: lVar13 = 0;
85: iVar7 = 1;
86: do {
87: *(int *)(pcVar17 + lVar13 * 4) = iVar11;
88: lVar13 = lVar13 + 1;
89: iVar7 = iVar7 * iVar11;
90: } while ((int)lVar13 < iVar21);
91: }
92: do {
93: iVar11 = 0;
94: bVar5 = false;
95: bVar6 = false;
96: if (0 < iVar21) {
97: do {
98: bVar5 = bVar6;
99: iVar22 = iVar11;
100: if (*(int *)(param_1 + 8) == 2) {
101: iVar22 = aiStack72[iVar11];
102: }
103: iVar1 = *(int *)(pcVar17 + (long)iVar22 * 4);
104: iVar18 = iVar1 + 1;
105: lVar13 = (long)(iVar7 / iVar1) * (long)iVar18;
106: if (lVar13 - lVar20 != 0 && lVar20 <= lVar13) break;
107: iVar11 = iVar11 + 1;
108: *(int *)(pcVar17 + (long)iVar22 * 4) = iVar18;
109: iVar7 = (int)lVar13;
110: bVar5 = true;
111: bVar6 = true;
112: } while (iVar11 < iVar21);
113: }
114: if (!bVar5) {
115: pcVar17 = *param_1;
116: if (*(int *)(param_1 + 0x12) == 3) {
117: *(int *)(pcVar17 + 0x2c) = iVar7;
118: *(undefined4 *)(pcVar17 + 0x30) = *(undefined4 *)(pcVar3 + 0x3c);
119: *(undefined4 *)(pcVar17 + 0x34) = *(undefined4 *)(pcVar3 + 0x40);
120: uVar2 = *(undefined4 *)(pcVar3 + 0x44);
121: *(undefined4 *)(pcVar17 + 0x28) = 0x5e;
122: *(undefined4 *)(pcVar17 + 0x38) = uVar2;
123: (**(code **)(pcVar17 + 8))(param_1,1);
124: }
125: else {
126: *(undefined4 *)(pcVar17 + 0x28) = 0x5f;
127: *(int *)(pcVar17 + 0x2c) = iVar7;
128: (**(code **)(*param_1 + 8))(param_1,1);
129: }
130: lVar13 = (**(code **)(param_1[1] + 0x10))(param_1,1,iVar7);
131: iVar21 = *(int *)(param_1 + 0x12);
132: lVar20 = 0;
133: iVar11 = iVar7;
134: if (0 < iVar21) {
135: do {
136: iVar22 = *(int *)(pcVar3 + lVar20 * 4 + 0x3c);
137: iVar1 = iVar11 / iVar22;
138: if (0 < iVar22) {
139: uVar12 = iVar22 - 1;
140: iVar21 = 0;
141: lVar16 = 0;
142: lVar14 = 0;
143: do {
144: lVar19 = lVar14;
145: iVar22 = iVar21;
146: while (iVar22 < iVar7) {
147: if (0 < iVar1) {
148: lVar15 = lVar19;
149: do {
150: *(char *)(*(long *)(lVar13 + lVar20 * 8) + lVar15) =
151: (char)((((int)uVar12 >> 1) + lVar16) / (long)(int)uVar12);
152: lVar15 = lVar15 + 1;
153: } while (lVar15 != (ulong)(iVar1 - 1) + 1 + lVar19);
154: }
155: iVar22 = iVar22 + iVar11;
156: lVar19 = lVar19 + iVar11;
157: }
158: lVar16 = lVar16 + 0xff;
159: iVar21 = iVar21 + iVar1;
160: lVar14 = lVar14 + iVar1;
161: } while (lVar16 != ((ulong)uVar12 + 1) * 0xff);
162: iVar21 = *(int *)(param_1 + 0x12);
163: }
164: iVar22 = (int)lVar20;
165: lVar20 = lVar20 + 1;
166: iVar11 = iVar1;
167: } while (iVar22 + 1 < iVar21);
168: }
169: *(long *)(pcVar3 + 0x20) = lVar13;
170: *(int *)(pcVar3 + 0x28) = iVar7;
171: FUN_00139170(param_1);
172: if (*(int *)(param_1 + 0xe) == 2) {
173: iVar21 = *(int *)(param_1 + 0x11);
174: if (0 < *(int *)(param_1 + 0x12)) {
175: iVar7 = 0;
176: pcVar17 = param_1[0x4e];
177: do {
178: iVar7 = iVar7 + 1;
179: uVar10 = (**(code **)(param_1[1] + 8))(param_1,1,(ulong)(iVar21 + 2) * 2);
180: *(undefined8 *)(pcVar17 + 0x70) = uVar10;
181: pcVar17 = pcVar17 + 8;
182: } while (iVar7 < *(int *)(param_1 + 0x12));
183: return;
184: }
185: }
186: return;
187: }
188: } while( true );
189: }
190: 
