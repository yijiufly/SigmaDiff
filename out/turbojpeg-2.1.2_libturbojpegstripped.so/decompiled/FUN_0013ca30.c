1: 
2: void FUN_0013ca30(long param_1,undefined8 param_2,long param_3,long *param_4)
3: 
4: {
5: undefined (*pauVar1) [16];
6: undefined auVar2 [16];
7: long lVar3;
8: int iVar4;
9: undefined (*pauVar5) [16];
10: int iVar6;
11: undefined (*pauVar7) [16];
12: long lVar8;
13: undefined (*pauVar9) [16];
14: ulong uVar10;
15: undefined (*pauVar11) [16];
16: ulong uVar12;
17: undefined uVar13;
18: undefined uVar14;
19: undefined uVar15;
20: undefined uVar16;
21: undefined uVar17;
22: undefined uVar18;
23: undefined uVar19;
24: undefined uVar20;
25: undefined uVar21;
26: undefined uVar22;
27: undefined uVar23;
28: undefined uVar24;
29: 
30: lVar3 = *param_4;
31: iVar6 = *(int *)(param_1 + 0x19c);
32: if (0 < iVar6) {
33: lVar8 = 1;
34: do {
35: pauVar5 = *(undefined (**) [16])(lVar3 + -8 + lVar8 * 8);
36: pauVar9 = *(undefined (**) [16])(param_3 + -8 + lVar8 * 8);
37: pauVar1 = (undefined (*) [16])(*pauVar5 + *(uint *)(param_1 + 0x88));
38: if (pauVar5 < pauVar1) {
39: uVar10 = (ulong)*(uint *)(param_1 + 0x88) - 1;
40: pauVar7 = (undefined (*) [16])(*pauVar5 + 2);
41: uVar12 = (uVar10 >> 1) + 1;
42: if ((pauVar9 < (undefined (*) [16])(*pauVar5 + (uVar10 & 0xfffffffffffffffe) + 2) &&
43: pauVar5 < (undefined (*) [16])(*pauVar9 + uVar12)) || (uVar12 < 0x10)) {
44: while( true ) {
45: uVar13 = (*pauVar9)[0];
46: (*pauVar5)[0] = uVar13;
47: pauVar7[-1][0xf] = uVar13;
48: if (pauVar1 <= pauVar7) break;
49: pauVar5 = pauVar7;
50: pauVar7 = (undefined (*) [16])(*pauVar7 + 2);
51: pauVar9 = (undefined (*) [16])(*pauVar9 + 1);
52: }
53: }
54: else {
55: if (0x1d < (ulong)((long)pauVar1 + (1 - (long)pauVar7))) {
56: uVar10 = 0;
57: pauVar7 = pauVar5;
58: pauVar11 = pauVar9;
59: do {
60: auVar2 = *pauVar11;
61: uVar10 = uVar10 + 1;
62: pauVar11 = pauVar11[1];
63: uVar16 = SUB161(auVar2 >> 0x38,0);
64: uVar15 = SUB161(auVar2 >> 0x30,0);
65: uVar14 = SUB161(auVar2 >> 0x28,0);
66: uVar13 = SUB161(auVar2 >> 0x20,0);
67: uVar17 = SUB161(auVar2 >> 0x40,0);
68: uVar18 = SUB161(auVar2 >> 0x48,0);
69: uVar19 = SUB161(auVar2 >> 0x50,0);
70: uVar20 = SUB161(auVar2 >> 0x58,0);
71: uVar21 = SUB161(auVar2 >> 0x60,0);
72: uVar22 = SUB161(auVar2 >> 0x68,0);
73: uVar23 = SUB161(auVar2 >> 0x70,0);
74: uVar24 = SUB161(auVar2 >> 0x78,0);
75: *pauVar7 = CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(
76: CONCAT97(CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610
77: (SUB166(CONCAT511(SUB165(CONCAT412(SUB164(
78: CONCAT313(SUB163(CONCAT214(SUB162(CONCAT115(uVar16
79: ,CONCAT114(uVar16,SUB1614(auVar2,0))) >> 0x70,0),
80: CONCAT113(uVar15,SUB1613(auVar2,0))) >> 0x68,0),
81: CONCAT112(uVar15,SUB1612(auVar2,0))) >> 0x60,0),
82: CONCAT111(uVar14,SUB1611(auVar2,0))) >> 0x58,0),
83: CONCAT110(uVar14,SUB1610(auVar2,0))) >> 0x50,0),
84: CONCAT19(uVar13,SUB169(auVar2,0))) >> 0x48,0),
85: CONCAT18(uVar13,SUB168(auVar2,0))) >> 0x40,0),
86: SUB161(auVar2 >> 0x18,0)),
87: (SUB167(auVar2,0) >> 0x18) << 0x30) >> 0x30,0),
88: SUB161(auVar2 >> 0x10,0)),
89: (SUB165(auVar2,0) >> 0x10) << 0x20) >> 0x20,0),
90: SUB161(auVar2 >> 8,0)),
91: (SUB163(auVar2,0) >> 8) << 0x10) >> 0x10,0),
92: SUB162(auVar2,0) & 0xff | (ushort)SUB161(auVar2,0) << 8);
93: pauVar7[1][0] = uVar17;
94: pauVar7[1][1] = uVar17;
95: pauVar7[1][2] = uVar18;
96: pauVar7[1][3] = uVar18;
97: pauVar7[1][4] = uVar19;
98: pauVar7[1][5] = uVar19;
99: pauVar7[1][6] = uVar20;
100: pauVar7[1][7] = uVar20;
101: pauVar7[1][8] = uVar21;
102: pauVar7[1][9] = uVar21;
103: pauVar7[1][10] = uVar22;
104: pauVar7[1][0xb] = uVar22;
105: pauVar7[1][0xc] = uVar23;
106: pauVar7[1][0xd] = uVar23;
107: pauVar7[1][0xe] = uVar24;
108: pauVar7[1][0xf] = uVar24;
109: pauVar7 = pauVar7[2];
110: } while (uVar10 < uVar12 >> 4);
111: uVar10 = uVar12 & 0xfffffffffffffff0;
112: pauVar9 = (undefined (*) [16])(*pauVar9 + uVar10);
113: pauVar5 = (undefined (*) [16])(*pauVar5 + uVar10 * 2);
114: if (uVar12 == uVar10) goto LAB_0013cc50;
115: pauVar7 = (undefined (*) [16])(*pauVar5 + 2);
116: }
117: uVar13 = (*pauVar9)[0];
118: (*pauVar5)[0] = uVar13;
119: (*pauVar5)[1] = uVar13;
120: if (pauVar7 < pauVar1) {
121: uVar13 = (*pauVar9)[1];
122: (*pauVar5)[2] = uVar13;
123: (*pauVar5)[3] = uVar13;
124: if ((undefined (*) [16])(*pauVar5 + 4) < pauVar1) {
125: uVar13 = (*pauVar9)[2];
126: (*pauVar5)[4] = uVar13;
127: (*pauVar5)[5] = uVar13;
128: if ((undefined (*) [16])(*pauVar5 + 6) < pauVar1) {
129: uVar13 = (*pauVar9)[3];
130: (*pauVar5)[6] = uVar13;
131: (*pauVar5)[7] = uVar13;
132: if ((undefined (*) [16])(*pauVar5 + 8) < pauVar1) {
133: uVar13 = (*pauVar9)[4];
134: (*pauVar5)[8] = uVar13;
135: (*pauVar5)[9] = uVar13;
136: if ((undefined (*) [16])(*pauVar5 + 10) < pauVar1) {
137: uVar13 = (*pauVar9)[5];
138: (*pauVar5)[10] = uVar13;
139: (*pauVar5)[0xb] = uVar13;
140: if ((undefined (*) [16])(*pauVar5 + 0xc) < pauVar1) {
141: uVar13 = (*pauVar9)[6];
142: (*pauVar5)[0xc] = uVar13;
143: (*pauVar5)[0xd] = uVar13;
144: if ((undefined (*) [16])(*pauVar5 + 0xe) < pauVar1) {
145: uVar13 = (*pauVar9)[7];
146: (*pauVar5)[0xe] = uVar13;
147: (*pauVar5)[0xf] = uVar13;
148: if (pauVar5[1] < pauVar1) {
149: uVar13 = (*pauVar9)[8];
150: pauVar5[1][0] = uVar13;
151: pauVar5[1][1] = uVar13;
152: if ((undefined (*) [16])(pauVar5[1] + 2) < pauVar1) {
153: uVar13 = (*pauVar9)[9];
154: pauVar5[1][2] = uVar13;
155: pauVar5[1][3] = uVar13;
156: if ((undefined (*) [16])(pauVar5[1] + 4) < pauVar1) {
157: uVar13 = (*pauVar9)[10];
158: pauVar5[1][4] = uVar13;
159: pauVar5[1][5] = uVar13;
160: if ((undefined (*) [16])(pauVar5[1] + 6) < pauVar1) {
161: uVar13 = (*pauVar9)[0xb];
162: pauVar5[1][6] = uVar13;
163: pauVar5[1][7] = uVar13;
164: if ((undefined (*) [16])(pauVar5[1] + 8) < pauVar1) {
165: uVar13 = (*pauVar9)[0xc];
166: pauVar5[1][8] = uVar13;
167: pauVar5[1][9] = uVar13;
168: if ((undefined (*) [16])(pauVar5[1] + 10) < pauVar1) {
169: uVar13 = (*pauVar9)[0xd];
170: pauVar5[1][10] = uVar13;
171: pauVar5[1][0xb] = uVar13;
172: if ((undefined (*) [16])(pauVar5[1] + 0xc) < pauVar1) {
173: uVar13 = (*pauVar9)[0xe];
174: pauVar5[1][0xc] = uVar13;
175: pauVar5[1][0xd] = uVar13;
176: }
177: }
178: }
179: }
180: }
181: }
182: }
183: }
184: }
185: }
186: }
187: }
188: }
189: }
190: }
191: LAB_0013cc50:
192: iVar6 = *(int *)(param_1 + 0x19c);
193: }
194: iVar4 = (int)lVar8;
195: lVar8 = lVar8 + 1;
196: } while (iVar4 < iVar6);
197: }
198: return;
199: }
200: 
