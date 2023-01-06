1: 
2: void FUN_001465d0(long param_1)
3: 
4: {
5: ulong uVar1;
6: int *piVar2;
7: long lVar3;
8: uint uVar4;
9: int iVar5;
10: uint uVar6;
11: long lVar7;
12: undefined (*pauVar8) [16];
13: int iVar9;
14: int *piVar10;
15: uint uVar11;
16: undefined auVar12 [16];
17: int iStack28;
18: int iVar13;
19: int iVar14;
20: 
21: lVar7 = *(long *)(param_1 + 0x270);
22: lVar3 = (***(code ***)(param_1 + 8))(param_1,1,0x7fc);
23: uVar1 = lVar3 + 0x3fc;
24: *(ulong *)(lVar7 + 0x50) = uVar1;
25: uVar6 = -(int)(uVar1 >> 2) & 3;
26: if (uVar6 == 0) {
27: iVar5 = 0x10;
28: iStack28 = 0;
29: }
30: else {
31: *(undefined4 *)(lVar3 + 0x3fc) = 0;
32: if (uVar6 == 1) {
33: iVar5 = 0xf;
34: iStack28 = 1;
35: }
36: else {
37: *(undefined4 *)(lVar3 + 0x400) = 1;
38: *(undefined4 *)(lVar3 + 0x3f8) = 0xffffffff;
39: if (uVar6 == 3) {
40: *(undefined4 *)(lVar3 + 0x404) = 2;
41: *(undefined4 *)(lVar3 + 0x3f4) = 0xfffffffe;
42: iVar5 = 0xd;
43: iStack28 = 3;
44: }
45: else {
46: iVar5 = 0xe;
47: iStack28 = 2;
48: }
49: }
50: }
51: piVar10 = (int *)(lVar3 + 0x3fc + (ulong)uVar6 * 4);
52: uVar4 = 0x10 - uVar6;
53: piVar2 = (int *)(lVar3 + 0x3f0 + (ulong)uVar6 * -4);
54: *piVar10 = iStack28;
55: piVar10[1] = iStack28 + 1;
56: piVar10[2] = iStack28 + 2;
57: piVar10[3] = iStack28 + 3;
58: *piVar2 = -(iStack28 + 3);
59: piVar2[1] = -(iStack28 + 2);
60: piVar2[2] = -(iStack28 + 1);
61: piVar2[3] = -iStack28;
62: auVar12 = ZEXT1216(SUB1612((undefined  [16])0x0 >> 0x20,0)) << 0x20;
63: iVar13 = SUB164(auVar12 >> 0x40,0) - (iStack28 + 6);
64: iVar14 = SUB164(auVar12 >> 0x60,0) - (iStack28 + 7);
65: piVar10[4] = iStack28 + 4;
66: piVar10[5] = iStack28 + 5;
67: piVar10[6] = iStack28 + 6;
68: piVar10[7] = iStack28 + 7;
69: piVar2[-4] = iVar14;
70: piVar2[-3] = iVar13;
71: piVar2[-2] = iVar13;
72: piVar2[-1] = iVar14;
73: auVar12 = ZEXT1216(SUB1612((undefined  [16])0x0 >> 0x20,0)) << 0x20;
74: iVar13 = SUB164(auVar12 >> 0x40,0) - (iStack28 + 10);
75: iVar14 = SUB164(auVar12 >> 0x60,0) - (iStack28 + 0xb);
76: piVar10[8] = iStack28 + 8;
77: piVar10[9] = iStack28 + 9;
78: piVar10[10] = iStack28 + 10;
79: piVar10[0xb] = iStack28 + 0xb;
80: piVar2[-8] = iVar14;
81: piVar2[-7] = iVar13;
82: piVar2[-6] = iVar13;
83: piVar2[-5] = iVar14;
84: if (uVar4 >> 2 == 4) {
85: *(undefined (*) [16])(piVar10 + 0xc) =
86: CONCAT412(iStack28 + 0xf,CONCAT48(iStack28 + 0xe,CONCAT44(iStack28 + 0xd,iStack28 + 0xc)));
87: *(undefined (*) [16])(piVar2 + -0xc) =
88: CONCAT412(-(iStack28 + 0xc),
89: CONCAT48(-(iStack28 + 0xd),CONCAT44(-(iStack28 + 0xe),-(iStack28 + 0xf))));
90: }
91: uVar11 = uVar4 & 0xfffffffc;
92: uVar6 = iStack28 + uVar11;
93: if (uVar4 != uVar11) {
94: *(uint *)(uVar1 + (long)(int)uVar6 * 4) = uVar6;
95: *(uint *)(uVar1 + (long)(int)-uVar6 * 4) = -uVar6;
96: if (iVar5 - uVar11 != 1) {
97: *(uint *)(uVar1 + (long)(int)(uVar6 + 1) * 4) = uVar6 + 1;
98: *(uint *)(uVar1 + (long)(int)~uVar6 * 4) = ~uVar6;
99: if (iVar5 - uVar11 != 2) {
100: *(uint *)(uVar1 + (long)(int)(uVar6 + 2) * 4) = uVar6 + 2;
101: *(uint *)(uVar1 + (long)(int)(-2 - uVar6) * 4) = -2 - uVar6;
102: }
103: }
104: }
105: lVar7 = 0x11;
106: iVar5 = 0x10;
107: piVar10 = (int *)(lVar3 + 0x3bc);
108: do {
109: *(int *)(lVar3 + 0x3f8 + lVar7 * 4) = iVar5;
110: *piVar10 = -iVar5;
111: uVar6 = (uint)lVar7;
112: lVar7 = lVar7 + 1;
113: iVar5 = iVar5 + (~uVar6 & 1);
114: piVar10 = piVar10 + -1;
115: } while (lVar7 != 0x31);
116: iVar13 = -iVar5;
117: uVar6 = -(int)(lVar3 + 0x4bcU >> 2) & 3;
118: if (uVar6 == 0) {
119: iVar14 = 0xd0;
120: iVar9 = 0x30;
121: }
122: else {
123: *(int *)(lVar3 + 0x4bc) = iVar5;
124: *(int *)(lVar3 + 0x33c) = iVar13;
125: if (uVar6 == 1) {
126: iVar14 = 0xcf;
127: iVar9 = 0x31;
128: }
129: else {
130: *(int *)(lVar3 + 0x4c0) = iVar5;
131: *(int *)(lVar3 + 0x338) = iVar13;
132: if (uVar6 == 3) {
133: *(int *)(lVar3 + 0x4c4) = iVar5;
134: *(int *)(lVar3 + 0x334) = iVar13;
135: iVar14 = 0xcd;
136: iVar9 = 0x33;
137: }
138: else {
139: iVar14 = 0xce;
140: iVar9 = 0x32;
141: }
142: }
143: }
144: uVar11 = 0xd0 - uVar6;
145: uVar4 = 0;
146: pauVar8 = (undefined (*) [16])(lVar3 + 0x330 + (ulong)uVar6 * -4);
147: piVar10 = (int *)(lVar3 + 0x4bc + (ulong)uVar6 * 4);
148: do {
149: uVar4 = uVar4 + 1;
150: *piVar10 = iVar5;
151: piVar10[1] = iVar5;
152: piVar10[2] = iVar5;
153: piVar10[3] = iVar5;
154: *pauVar8 = CONCAT412(iVar13,CONCAT48(iVar13,CONCAT44(iVar13,iVar13)));
155: pauVar8 = pauVar8[-1];
156: piVar10 = piVar10 + 4;
157: } while (uVar4 < uVar11 >> 2);
158: uVar4 = uVar11 & 0xfffffffc;
159: uVar6 = uVar4 + iVar9;
160: if (uVar11 != uVar4) {
161: *(int *)(uVar1 + (long)(int)uVar6 * 4) = iVar5;
162: *(int *)(uVar1 + (long)(int)-uVar6 * 4) = iVar13;
163: if (iVar14 - uVar4 != 1) {
164: *(int *)(uVar1 + (long)(int)(uVar6 + 1) * 4) = iVar5;
165: *(int *)(uVar1 + (long)(int)~uVar6 * 4) = iVar13;
166: if (iVar14 - uVar4 != 2) {
167: *(int *)(uVar1 + (long)(int)(uVar6 + 2) * 4) = iVar5;
168: *(int *)(uVar1 + (long)(int)(-2 - uVar6) * 4) = iVar13;
169: }
170: }
171: }
172: return;
173: }
174: 
