1: 
2: void FUN_00131b80(long param_1,undefined8 param_2,long param_3,long *param_4)
3: 
4: {
5: undefined *puVar1;
6: undefined auVar2 [16];
7: long lVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: undefined *puVar7;
12: undefined *puVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: ulong uVar11;
16: long lVar12;
17: ulong uVar13;
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
29: undefined uVar25;
30: 
31: lVar12 = 0;
32: iVar5 = *(int *)(param_1 + 0x19c);
33: lVar3 = *param_4;
34: if (0 < iVar5) {
35: do {
36: puVar9 = *(undefined **)(lVar3 + lVar12 * 8);
37: puVar10 = *(undefined **)(param_3 + lVar12 * 8);
38: puVar8 = puVar9 + *(uint *)(param_1 + 0x88);
39: if (puVar9 < puVar8) {
40: puVar1 = puVar9 + 2;
41: uVar11 = ((ulong)(puVar8 + (1 - (long)puVar1)) >> 1) + 1;
42: if ((puVar10 < puVar9 + uVar11 * 2 && puVar9 < puVar10 + uVar11) || (uVar11 < 0x10)) {
43: while( true ) {
44: puVar7 = puVar1;
45: uVar14 = *puVar10;
46: *puVar9 = uVar14;
47: puVar7[-1] = uVar14;
48: if (puVar8 <= puVar7) break;
49: puVar1 = puVar7 + 2;
50: puVar9 = puVar7;
51: puVar10 = puVar10 + 1;
52: }
53: }
54: else {
55: lVar6 = 0;
56: uVar13 = 0;
57: do {
58: auVar2 = *(undefined (*) [16])(puVar10 + lVar6);
59: uVar13 = uVar13 + 1;
60: uVar17 = SUB161(auVar2 >> 0x38,0);
61: uVar16 = SUB161(auVar2 >> 0x30,0);
62: uVar15 = SUB161(auVar2 >> 0x28,0);
63: uVar14 = SUB161(auVar2 >> 0x20,0);
64: uVar18 = SUB161(auVar2 >> 0x40,0);
65: uVar19 = SUB161(auVar2 >> 0x48,0);
66: uVar20 = SUB161(auVar2 >> 0x50,0);
67: uVar21 = SUB161(auVar2 >> 0x58,0);
68: uVar22 = SUB161(auVar2 >> 0x60,0);
69: uVar23 = SUB161(auVar2 >> 0x68,0);
70: uVar24 = SUB161(auVar2 >> 0x70,0);
71: uVar25 = SUB161(auVar2 >> 0x78,0);
72: *(undefined (*) [16])(puVar9 + lVar6 * 2) =
73: CONCAT142(SUB1614(CONCAT133(CONCAT121(SUB1612(CONCAT115(CONCAT101(SUB1610(CONCAT97(
74: CONCAT81(SUB168(CONCAT79(SUB167(CONCAT610(SUB166(
75: CONCAT511(SUB165(CONCAT412(SUB164(CONCAT313(SUB163
76: (CONCAT214(SUB162(CONCAT115(uVar17,CONCAT114(
77: uVar17,SUB1614(auVar2,0))) >> 0x70,0),
78: CONCAT113(uVar16,SUB1613(auVar2,0))) >> 0x68,0),
79: CONCAT112(uVar16,SUB1612(auVar2,0))) >> 0x60,0),
80: CONCAT111(uVar15,SUB1611(auVar2,0))) >> 0x58,0),
81: CONCAT110(uVar15,SUB1610(auVar2,0))) >> 0x50,0),
82: CONCAT19(uVar14,SUB169(auVar2,0))) >> 0x48,0),
83: CONCAT18(uVar14,SUB168(auVar2,0))) >> 0x40,0),
84: SUB161(auVar2 >> 0x18,0)),
85: (SUB167(auVar2,0) >> 0x18) << 0x30) >> 0x30,0),
86: SUB161(auVar2 >> 0x10,0)),
87: (SUB165(auVar2,0) >> 0x10) << 0x20) >> 0x20,0),
88: SUB161(auVar2 >> 8,0)),
89: (SUB163(auVar2,0) >> 8) << 0x10) >> 0x10,0),
90: SUB162(auVar2,0) & 0xff | (ushort)SUB161(auVar2,0) << 8);
91: puVar1 = puVar9 + lVar6 * 2 + 0x10;
92: *puVar1 = uVar18;
93: puVar1[1] = uVar18;
94: puVar1[2] = uVar19;
95: puVar1[3] = uVar19;
96: puVar1[4] = uVar20;
97: puVar1[5] = uVar20;
98: puVar1[6] = uVar21;
99: puVar1[7] = uVar21;
100: puVar1[8] = uVar22;
101: puVar1[9] = uVar22;
102: puVar1[10] = uVar23;
103: puVar1[0xb] = uVar23;
104: puVar1[0xc] = uVar24;
105: puVar1[0xd] = uVar24;
106: puVar1[0xe] = uVar25;
107: puVar1[0xf] = uVar25;
108: lVar6 = lVar6 + 0x10;
109: } while (uVar13 < uVar11 >> 4);
110: puVar10 = puVar10 + (uVar11 & 0xfffffffffffffff0);
111: puVar9 = puVar9 + (uVar11 >> 4) * 0x20;
112: if (uVar11 != (uVar11 & 0xfffffffffffffff0)) {
113: uVar14 = *puVar10;
114: *puVar9 = uVar14;
115: puVar9[1] = uVar14;
116: if (puVar9 + 2 < puVar8) {
117: uVar14 = puVar10[1];
118: puVar9[2] = uVar14;
119: puVar9[3] = uVar14;
120: if (puVar9 + 4 < puVar8) {
121: uVar14 = puVar10[2];
122: puVar9[4] = uVar14;
123: puVar9[5] = uVar14;
124: if (puVar9 + 6 < puVar8) {
125: uVar14 = puVar10[3];
126: puVar9[6] = uVar14;
127: puVar9[7] = uVar14;
128: if (puVar9 + 8 < puVar8) {
129: uVar14 = puVar10[4];
130: puVar9[8] = uVar14;
131: puVar9[9] = uVar14;
132: if (puVar9 + 10 < puVar8) {
133: uVar14 = puVar10[5];
134: puVar9[10] = uVar14;
135: puVar9[0xb] = uVar14;
136: if (puVar9 + 0xc < puVar8) {
137: uVar14 = puVar10[6];
138: puVar9[0xc] = uVar14;
139: puVar9[0xd] = uVar14;
140: if (puVar9 + 0xe < puVar8) {
141: uVar14 = puVar10[7];
142: puVar9[0xe] = uVar14;
143: puVar9[0xf] = uVar14;
144: if (puVar9 + 0x10 < puVar8) {
145: uVar14 = puVar10[8];
146: puVar9[0x10] = uVar14;
147: puVar9[0x11] = uVar14;
148: if (puVar9 + 0x12 < puVar8) {
149: uVar14 = puVar10[9];
150: puVar9[0x12] = uVar14;
151: puVar9[0x13] = uVar14;
152: if (puVar9 + 0x14 < puVar8) {
153: uVar14 = puVar10[10];
154: puVar9[0x14] = uVar14;
155: puVar9[0x15] = uVar14;
156: if (puVar9 + 0x16 < puVar8) {
157: uVar14 = puVar10[0xb];
158: puVar9[0x16] = uVar14;
159: puVar9[0x17] = uVar14;
160: if (puVar9 + 0x18 < puVar8) {
161: uVar14 = puVar10[0xc];
162: puVar9[0x18] = uVar14;
163: puVar9[0x19] = uVar14;
164: if (puVar9 + 0x1a < puVar8) {
165: uVar14 = puVar10[0xd];
166: puVar9[0x1a] = uVar14;
167: puVar9[0x1b] = uVar14;
168: if (puVar9 + 0x1c < puVar8) {
169: uVar14 = puVar10[0xe];
170: puVar9[0x1c] = uVar14;
171: puVar9[0x1d] = uVar14;
172: }
173: }
174: }
175: }
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
188: iVar5 = *(int *)(param_1 + 0x19c);
189: }
190: iVar4 = (int)lVar12;
191: lVar12 = lVar12 + 1;
192: } while (iVar4 + 1 < iVar5);
193: }
194: return;
195: }
196: 
