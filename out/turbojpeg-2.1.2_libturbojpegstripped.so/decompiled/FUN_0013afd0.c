1: 
2: void FUN_0013afd0(code **param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: undefined4 uVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: code *pcVar6;
11: code *pcVar7;
12: bool bVar8;
13: int iVar9;
14: long lVar10;
15: long lVar11;
16: int iVar12;
17: int *piVar13;
18: int iVar14;
19: long lVar15;
20: 
21: pcVar4 = param_1[0x4a];
22: iVar9 = *(int *)(param_1 + 0x42);
23: iVar1 = *(int *)((long)param_1 + 0x214);
24: iVar2 = *(int *)((long)param_1 + 0x20c);
25: iVar14 = *(int *)(param_1 + 0x43);
26: if (iVar2 == 0) {
27: if (iVar9 == 0) {
28: if (iVar1 == 0) {
29: if (iVar14 < 0xe) goto LAB_0013b038;
30: }
31: else {
32: bVar8 = false;
33: LAB_0013b3c6:
34: if (iVar1 + -1 == iVar14) goto LAB_0013b242;
35: }
36: }
37: LAB_0013b019:
38: ppcVar5 = (code **)*param_1;
39: *(int *)(ppcVar5 + 7) = iVar14;
40: *(undefined4 *)(ppcVar5 + 5) = 0x10;
41: *(int *)((long)ppcVar5 + 0x2c) = iVar2;
42: *(int *)(ppcVar5 + 6) = iVar9;
43: *(int *)((long)ppcVar5 + 0x34) = iVar1;
44: (**ppcVar5)();
45: }
46: else {
47: if (*(int *)(param_1 + 0x36) != 1) goto LAB_0013b019;
48: bVar8 = 0x3f < iVar9 || iVar9 < iVar2;
49: if (iVar1 != 0) goto LAB_0013b3c6;
50: LAB_0013b242:
51: if ((0xd < iVar14) || (bVar8)) goto LAB_0013b019;
52: }
53: LAB_0013b038:
54: iVar9 = *(int *)(param_1 + 0x36);
55: lVar15 = 1;
56: if (0 < iVar9) {
57: do {
58: iVar9 = *(int *)(param_1 + 7);
59: iVar1 = *(int *)(param_1[lVar15 + 0x36] + 4);
60: pcVar6 = param_1[0x18];
61: piVar13 = (int *)(pcVar6 + (long)iVar1 * 0x100);
62: if ((iVar2 != 0) && (*piVar13 < 0)) {
63: pcVar7 = *param_1;
64: *(undefined4 *)(pcVar7 + 0x28) = 0x73;
65: *(int *)(pcVar7 + 0x2c) = iVar1;
66: *(undefined4 *)(pcVar7 + 0x30) = 0;
67: (**(code **)(pcVar7 + 8))(param_1,0xffffffff);
68: }
69: iVar14 = 1;
70: if (*(int *)((long)param_1 + 0x20c) < 1) {
71: iVar14 = *(int *)((long)param_1 + 0x20c);
72: }
73: lVar10 = (long)(iVar14 + 1);
74: lVar11 = iVar14 - lVar10;
75: pcVar6 = pcVar6 + lVar11 * 4 + (long)(iVar9 + iVar1) * 0x100;
76: do {
77: if (*(int *)((long)param_1 + 0xac) < 2) {
78: *(undefined4 *)(pcVar6 + lVar10 * 4) = 0;
79: }
80: else {
81: *(int *)(pcVar6 + lVar10 * 4) = piVar13[lVar11 + lVar10];
82: }
83: iVar9 = *(int *)(param_1 + 0x42);
84: iVar14 = (int)lVar10;
85: lVar10 = lVar10 + 1;
86: iVar12 = 9;
87: if (8 < iVar9) {
88: iVar12 = iVar9;
89: }
90: } while (iVar14 <= iVar12);
91: iVar14 = *(int *)((long)param_1 + 0x20c);
92: if (iVar14 <= iVar9) {
93: piVar13 = piVar13 + iVar14;
94: do {
95: while( true ) {
96: iVar9 = 0;
97: if (-1 < *piVar13) {
98: iVar9 = *piVar13;
99: }
100: if (*(int *)((long)param_1 + 0x214) == iVar9) break;
101: pcVar6 = *param_1;
102: *(int *)(pcVar6 + 0x30) = iVar14;
103: *(undefined4 *)(pcVar6 + 0x28) = 0x73;
104: iVar14 = iVar14 + 1;
105: *(int *)(pcVar6 + 0x2c) = iVar1;
106: (**(code **)(pcVar6 + 8))(param_1,0xffffffff);
107: *piVar13 = *(int *)(param_1 + 0x43);
108: piVar13 = piVar13 + 1;
109: if (*(int *)(param_1 + 0x42) < iVar14) goto LAB_0013b1a1;
110: }
111: iVar14 = iVar14 + 1;
112: *piVar13 = *(int *)(param_1 + 0x43);
113: piVar13 = piVar13 + 1;
114: } while (iVar14 <= *(int *)(param_1 + 0x42));
115: }
116: LAB_0013b1a1:
117: iVar9 = *(int *)(param_1 + 0x36);
118: iVar1 = (int)lVar15;
119: lVar15 = lVar15 + 1;
120: } while (iVar1 < iVar9);
121: }
122: iVar1 = *(int *)((long)param_1 + 0x214);
123: if (iVar1 == 0) {
124: if (iVar2 != 0) {
125: *(code **)(pcVar4 + 8) = FUN_0013bcb0;
126: LAB_0013b34b:
127: if (0 < iVar9) {
128: lVar15 = 1;
129: do {
130: iVar9 = *(int *)(param_1[lVar15 + 0x36] + 0x18);
131: FUN_0012fb00(param_1,0,(long)iVar9);
132: iVar1 = (int)lVar15;
133: *(undefined8 *)(pcVar4 + 0x60) = *(undefined8 *)(pcVar4 + (long)iVar9 * 8 + 0x40);
134: iVar9 = *(int *)(param_1 + 0x36);
135: *(undefined4 *)(pcVar4 + lVar15 * 4 + 0x28) = 0;
136: lVar15 = lVar15 + 1;
137: } while (iVar1 < iVar9);
138: }
139: goto LAB_0013b302;
140: }
141: *(code **)(pcVar4 + 8) = FUN_0013c050;
142: }
143: else {
144: if (iVar2 != 0) {
145: *(code **)(pcVar4 + 8) = FUN_0013b490;
146: goto LAB_0013b34b;
147: }
148: *(code **)(pcVar4 + 8) = FUN_0013bae0;
149: }
150: if (0 < iVar9) {
151: if (iVar1 == 0) {
152: FUN_0012fb00(param_1,1,(long)*(int *)(param_1[0x37] + 0x14),
153: pcVar4 + (long)*(int *)(param_1[0x37] + 0x14) * 8 + 0x40);
154: iVar9 = *(int *)(param_1 + 0x36);
155: }
156: *(undefined4 *)(pcVar4 + 0x2c) = 0;
157: if (1 < iVar9) {
158: if (*(int *)((long)param_1 + 0x214) == 0) {
159: FUN_0012fb00(param_1,1,(long)*(int *)(param_1[0x38] + 0x14),
160: pcVar4 + (long)*(int *)(param_1[0x38] + 0x14) * 8 + 0x40);
161: iVar9 = *(int *)(param_1 + 0x36);
162: }
163: *(undefined4 *)(pcVar4 + 0x30) = 0;
164: if (2 < iVar9) {
165: if (*(int *)((long)param_1 + 0x214) == 0) {
166: FUN_0012fb00(param_1,1,(long)*(int *)(param_1[0x39] + 0x14));
167: iVar9 = *(int *)(param_1 + 0x36);
168: }
169: *(undefined4 *)(pcVar4 + 0x34) = 0;
170: if (3 < iVar9) {
171: if (*(int *)((long)param_1 + 0x214) == 0) {
172: FUN_0012fb00(param_1,1,(long)*(int *)(param_1[0x3a] + 0x14),
173: pcVar4 + (long)*(int *)(param_1[0x3a] + 0x14) * 8 + 0x40);
174: }
175: *(undefined4 *)(pcVar4 + 0x38) = 0;
176: }
177: }
178: }
179: }
180: LAB_0013b302:
181: uVar3 = *(undefined4 *)(param_1 + 0x2e);
182: *(undefined4 *)(pcVar4 + 0x20) = 0;
183: *(undefined8 *)(pcVar4 + 0x18) = 0;
184: *(undefined4 *)(pcVar4 + 0x10) = 0;
185: *(undefined4 *)(pcVar4 + 0x28) = 0;
186: *(undefined4 *)(pcVar4 + 0x3c) = uVar3;
187: return;
188: }
189: 
