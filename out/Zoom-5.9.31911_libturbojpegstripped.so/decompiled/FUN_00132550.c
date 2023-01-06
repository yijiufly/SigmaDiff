1: 
2: void FUN_00132550(long param_1,undefined8 param_2,long param_3,long *param_4)
3: 
4: {
5: undefined *puVar1;
6: undefined auVar2 [16];
7: long lVar3;
8: long lVar4;
9: undefined *puVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: int iVar8;
13: int iVar9;
14: ulong uVar10;
15: undefined *puVar11;
16: ulong uVar12;
17: long lVar13;
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
31: lVar13 = 0;
32: lVar3 = *param_4;
33: iVar8 = 0;
34: if (0 < *(int *)(param_1 + 0x19c)) {
35: do {
36: puVar11 = *(undefined **)(lVar3 + lVar13 * 2);
37: puVar7 = *(undefined **)(param_3 + lVar13);
38: puVar6 = puVar11 + *(uint *)(param_1 + 0x88);
39: if (puVar11 < puVar6) {
40: puVar1 = puVar11 + 2;
41: uVar10 = ((ulong)(puVar6 + (1 - (long)puVar1)) >> 1) + 1;
42: if ((puVar7 < puVar11 + uVar10 * 2 && puVar11 < puVar7 + uVar10) || (uVar10 < 0x10)) {
43: while( true ) {
44: puVar5 = puVar1;
45: uVar14 = *puVar7;
46: *puVar11 = uVar14;
47: puVar5[-1] = uVar14;
48: if (puVar6 <= puVar5) break;
49: puVar1 = puVar5 + 2;
50: puVar7 = puVar7 + 1;
51: puVar11 = puVar5;
52: }
53: }
54: else {
55: lVar4 = 0;
56: uVar12 = 0;
57: do {
58: auVar2 = *(undefined (*) [16])(puVar7 + lVar4);
59: uVar12 = uVar12 + 1;
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
72: *(undefined (*) [16])(puVar11 + lVar4 * 2) =
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
91: puVar1 = puVar11 + lVar4 * 2 + 0x10;
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
108: lVar4 = lVar4 + 0x10;
109: } while (uVar12 < uVar10 >> 4);
110: puVar7 = puVar7 + (uVar10 & 0xfffffffffffffff0);
111: puVar11 = puVar11 + (uVar10 >> 4) * 0x20;
112: if (uVar10 != (uVar10 & 0xfffffffffffffff0)) {
113: uVar14 = *puVar7;
114: *puVar11 = uVar14;
115: puVar11[1] = uVar14;
116: if (puVar11 + 2 < puVar6) {
117: uVar14 = puVar7[1];
118: puVar11[2] = uVar14;
119: puVar11[3] = uVar14;
120: if (puVar11 + 4 < puVar6) {
121: uVar14 = puVar7[2];
122: puVar11[4] = uVar14;
123: puVar11[5] = uVar14;
124: if (puVar11 + 6 < puVar6) {
125: uVar14 = puVar7[3];
126: puVar11[6] = uVar14;
127: puVar11[7] = uVar14;
128: if (puVar11 + 8 < puVar6) {
129: uVar14 = puVar7[4];
130: puVar11[8] = uVar14;
131: puVar11[9] = uVar14;
132: if (puVar11 + 10 < puVar6) {
133: uVar14 = puVar7[5];
134: puVar11[10] = uVar14;
135: puVar11[0xb] = uVar14;
136: if (puVar11 + 0xc < puVar6) {
137: uVar14 = puVar7[6];
138: puVar11[0xc] = uVar14;
139: puVar11[0xd] = uVar14;
140: if (puVar11 + 0xe < puVar6) {
141: uVar14 = puVar7[7];
142: puVar11[0xe] = uVar14;
143: puVar11[0xf] = uVar14;
144: if (puVar11 + 0x10 < puVar6) {
145: uVar14 = puVar7[8];
146: puVar11[0x10] = uVar14;
147: puVar11[0x11] = uVar14;
148: if (puVar11 + 0x12 < puVar6) {
149: uVar14 = puVar7[9];
150: puVar11[0x12] = uVar14;
151: puVar11[0x13] = uVar14;
152: if (puVar11 + 0x14 < puVar6) {
153: uVar14 = puVar7[10];
154: puVar11[0x14] = uVar14;
155: puVar11[0x15] = uVar14;
156: if (puVar11 + 0x16 < puVar6) {
157: uVar14 = puVar7[0xb];
158: puVar11[0x16] = uVar14;
159: puVar11[0x17] = uVar14;
160: if (puVar11 + 0x18 < puVar6) {
161: uVar14 = puVar7[0xc];
162: puVar11[0x18] = uVar14;
163: puVar11[0x19] = uVar14;
164: if (puVar11 + 0x1a < puVar6) {
165: uVar14 = puVar7[0xd];
166: puVar11[0x1a] = uVar14;
167: puVar11[0x1b] = uVar14;
168: if (puVar11 + 0x1c < puVar6) {
169: uVar14 = puVar7[0xe];
170: puVar11[0x1c] = uVar14;
171: puVar11[0x1d] = uVar14;
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
188: }
189: iVar9 = iVar8 + 2;
190: FUN_0013be50(lVar3,iVar8,lVar3,iVar8 + 1,1);
191: lVar13 = lVar13 + 8;
192: iVar8 = iVar9;
193: } while (*(int *)(param_1 + 0x19c) != iVar9 && iVar9 <= *(int *)(param_1 + 0x19c));
194: }
195: return;
196: }
197: 
