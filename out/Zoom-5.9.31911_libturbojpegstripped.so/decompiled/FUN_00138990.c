1: 
2: void FUN_00138990(long param_1,long param_2,long param_3,long param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: short *psVar2;
7: int *piVar3;
8: int iVar4;
9: long lVar5;
10: int *piVar6;
11: int iVar7;
12: long lVar8;
13: undefined *puVar9;
14: int iVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: int iVar14;
19: int iVar15;
20: int iVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: int aiStack184 [8];
25: int aiStack152 [8];
26: int aiStack120 [8];
27: int aiStack88 [10];
28: 
29: param_3 = param_3 + 2;
30: piVar3 = aiStack184;
31: iVar7 = 7;
32: lVar5 = *(long *)(param_1 + 0x1a8) + 0x80;
33: piVar6 = piVar3;
34: psVar2 = *(short **)(param_2 + 0x58);
35: do {
36: if (iVar7 != 3) {
37: iVar16 = (int)*(short *)(param_3 + 0x1e);
38: if ((*(short *)(param_3 + 0xe) == 0) && (*(short *)(param_3 + 0x1e) == 0)) {
39: iVar4 = (int)*(short *)(param_3 + 0x2e);
40: if (*(short *)(param_3 + 0x2e) != 0) {
41: iVar10 = (int)*(short *)(param_3 + 0x5e);
42: iVar15 = (int)*(short *)(param_3 + 0x6e);
43: iVar16 = 0;
44: iVar14 = (int)*(short *)(param_3 + 0x4e);
45: goto LAB_00138a00;
46: }
47: iVar14 = (int)*(short *)(param_3 + 0x4e);
48: iVar10 = (int)*(short *)(param_3 + 0x5e);
49: iVar15 = (int)*(short *)(param_3 + 0x6e);
50: if (*(short *)(param_3 + 0x4e) != 0) {
51: iVar4 = 0;
52: iVar16 = 0;
53: goto LAB_00138a00;
54: }
55: if (*(short *)(param_3 + 0x5e) != 0) {
56: iVar4 = 0;
57: iVar14 = 0;
58: iVar16 = 0;
59: goto LAB_00138a00;
60: }
61: if (*(short *)(param_3 + 0x6e) != 0) {
62: iVar4 = 0;
63: iVar14 = 0;
64: iVar10 = 0;
65: iVar16 = 0;
66: goto LAB_00138a00;
67: }
68: iVar16 = (int)((long)((int)*(short *)(param_3 + -2) * (int)*psVar2) << 2);
69: *piVar6 = iVar16;
70: piVar6[8] = iVar16;
71: piVar6[0x10] = iVar16;
72: piVar6[0x18] = iVar16;
73: }
74: else {
75: iVar10 = (int)*(short *)(param_3 + 0x5e);
76: iVar15 = (int)*(short *)(param_3 + 0x6e);
77: iVar14 = (int)*(short *)(param_3 + 0x4e);
78: iVar4 = (int)*(short *)(param_3 + 0x2e);
79: LAB_00138a00:
80: lVar8 = (long)((int)*(short *)(param_3 + -2) * (int)*psVar2) * 0x4000;
81: lVar17 = (long)(iVar16 * psVar2[0x10]) * 0x3b21 + (long)(iVar10 * psVar2[0x30]) * -0x187e;
82: lVar11 = lVar8 + lVar17;
83: lVar8 = lVar8 - lVar17;
84: lVar17 = (long)((int)*(short *)(param_3 + 0xe) * (int)psVar2[8]);
85: lVar18 = (long)(iVar14 * psVar2[0x28]) * 0x2e75 + (long)(iVar15 * psVar2[0x38]) * -0x6c2 +
86: (long)(iVar4 * psVar2[0x18]) * -0x4587 + lVar17 * 0x21f9;
87: lVar17 = (long)(iVar4 * psVar2[0x18]) * 0x1ccd +
88: (long)(iVar14 * psVar2[0x28]) * -0x133e + (long)(iVar15 * psVar2[0x38]) * -0x1050 +
89: lVar17 * 0x5203;
90: piVar6[0x18] = (int)((lVar11 - lVar17) + 0x800 >> 0xc);
91: *piVar6 = (int)(lVar11 + 0x800 + lVar17 >> 0xc);
92: piVar6[8] = (int)(lVar8 + 0x800 + lVar18 >> 0xc);
93: piVar6[0x10] = (int)((lVar8 - lVar18) + 0x800 >> 0xc);
94: }
95: if (iVar7 == 0) break;
96: }
97: piVar6 = piVar6 + 1;
98: param_3 = param_3 + 2;
99: iVar7 = iVar7 + -1;
100: psVar2 = psVar2 + 1;
101: } while( true );
102: lVar11 = 0;
103: do {
104: iVar7 = piVar3[1];
105: puVar9 = (undefined *)((ulong)param_5 + *(long *)(param_4 + lVar11));
106: iVar16 = piVar3[2];
107: if ((iVar7 == 0) && (iVar16 == 0)) {
108: iVar4 = piVar3[3];
109: lVar8 = (long)iVar4;
110: if (iVar4 != 0) {
111: lVar19 = (long)piVar3[6];
112: lVar17 = (long)piVar3[7];
113: lVar18 = (long)piVar3[5];
114: goto LAB_00138ba8;
115: }
116: iVar10 = piVar3[5];
117: lVar18 = (long)iVar10;
118: iVar14 = piVar3[6];
119: lVar19 = (long)iVar14;
120: lVar17 = (long)piVar3[7];
121: iVar16 = iVar4;
122: if (iVar10 != 0) goto LAB_00138ba8;
123: if (iVar14 != 0) {
124: lVar8 = 0;
125: iVar16 = iVar10;
126: goto LAB_00138ba8;
127: }
128: if (piVar3[7] != 0) {
129: lVar8 = 0;
130: lVar18 = 0;
131: iVar16 = iVar14;
132: goto LAB_00138ba8;
133: }
134: uVar1 = *(undefined *)(lVar5 + (ulong)((uint)((long)*piVar3 + 0x10 >> 5) & 0x3ff));
135: *puVar9 = uVar1;
136: puVar9[1] = uVar1;
137: puVar9[2] = uVar1;
138: puVar9[3] = uVar1;
139: }
140: else {
141: lVar19 = (long)piVar3[6];
142: lVar17 = (long)piVar3[7];
143: lVar18 = (long)piVar3[5];
144: lVar8 = (long)piVar3[3];
145: LAB_00138ba8:
146: lVar12 = (long)iVar16 * 0x3b21 + lVar19 * -0x187e;
147: lVar19 = (long)*piVar3 * 0x4000 + lVar12;
148: lVar12 = (long)*piVar3 * 0x4000 - lVar12;
149: lVar13 = lVar18 * 0x2e75 + lVar17 * -0x6c2 + lVar8 * -0x4587 + (long)iVar7 * 0x21f9;
150: lVar17 = lVar17 * -0x1050 + lVar18 * -0x133e + lVar8 * 0x1ccd + (long)iVar7 * 0x5203;
151: *puVar9 = *(undefined *)(lVar5 + (ulong)((uint)(lVar19 + 0x40000 + lVar17 >> 0x13) & 0x3ff));
152: puVar9[3] = *(undefined *)
153: (lVar5 + (ulong)((uint)((lVar19 - lVar17) + 0x40000 >> 0x13) & 0x3ff));
154: puVar9[1] = *(undefined *)(lVar5 + (ulong)((uint)(lVar12 + 0x40000 + lVar13 >> 0x13) & 0x3ff))
155: ;
156: puVar9[2] = *(undefined *)
157: (lVar5 + (ulong)((uint)((lVar12 - lVar13) + 0x40000 >> 0x13) & 0x3ff));
158: }
159: piVar3 = piVar3 + 8;
160: lVar11 = lVar11 + 8;
161: if (lVar11 == 0x20) {
162: return;
163: }
164: } while( true );
165: }
166: 
