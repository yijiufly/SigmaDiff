1: 
2: undefined8 FUN_0014c040(long param_1,long *param_2)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: byte bVar7;
12: int iVar8;
13: uint uVar9;
14: int *piVar10;
15: int iVar11;
16: long lVar12;
17: int iVar13;
18: long lVar14;
19: int iStack84;
20: 
21: lVar4 = *(long *)(param_1 + 0x1f0);
22: if (*(int *)(param_1 + 0x118) != 0) {
23: iVar8 = *(int *)(lVar4 + 0x60);
24: if (iVar8 == 0) {
25: FUN_0014b810();
26: iVar8 = *(int *)(param_1 + 0x118);
27: *(uint *)(lVar4 + 100) = *(int *)(lVar4 + 100) + 1U & 7;
28: }
29: *(int *)(lVar4 + 0x60) = iVar8 + -1;
30: }
31: iVar8 = *(int *)(param_1 + 0x1a0);
32: lVar5 = *param_2;
33: iVar3 = *(int *)(*(long *)(param_1 + 0x148) + 0x18);
34: iVar13 = iVar8;
35: iStack84 = iVar8;
36: if (0 < iVar8) {
37: piVar10 = (int *)(&DAT_0018f100 + (long)iVar8 * 4);
38: LAB_0014c0ce:
39: sVar2 = *(short *)(lVar5 + (long)*piVar10 * 2);
40: iVar6 = (int)sVar2;
41: iVar11 = iVar6;
42: if (sVar2 < 0) {
43: iVar11 = -iVar6;
44: }
45: if (iVar11 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f) == 0) goto LAB_0014c0c0;
46: piVar10 = (int *)(&DAT_0018f100 + (long)(iVar13 + -1) * 4);
47: iStack84 = iVar13;
48: while( true ) {
49: if (iVar6 < 0) {
50: iVar6 = -iVar6;
51: }
52: if ((iVar6 >> ((byte)*(undefined4 *)(param_1 + 0x1a4) & 0x1f) != 0) ||
53: (iStack84 = iStack84 + -1, iStack84 == 0)) break;
54: iVar11 = *piVar10;
55: piVar10 = piVar10 + -1;
56: iVar6 = (int)*(short *)(lVar5 + (long)iVar11 * 2);
57: }
58: }
59: LAB_0014c11f:
60: iVar11 = *(int *)(param_1 + 0x19c);
61: if (iVar11 <= iVar13) {
62: LAB_0014c148:
63: lVar12 = (long)(iVar11 * 3 + -3) + *(long *)(lVar4 + 8 + ((long)iVar3 + 0x1c) * 8);
64: if (iStack84 < iVar11) {
65: FUN_0014a8b0(param_1,lVar12);
66: }
67: lVar14 = (long)iVar11;
68: do {
69: iVar8 = (int)*(short *)(lVar5 + (long)*(int *)(&DAT_0018f100 + lVar14 * 4) * 2);
70: bVar7 = (byte)*(undefined4 *)(param_1 + 0x1a8);
71: if (iVar8 < 0) {
72: uVar9 = -iVar8 >> (bVar7 & 0x1f);
73: if (uVar9 != 0) goto code_r0x0014c1b1;
74: }
75: else {
76: uVar9 = iVar8 >> (bVar7 & 0x1f);
77: if (uVar9 != 0) {
78: if (uVar9 >> 1 != 0) goto LAB_0014c270;
79: FUN_0014ac60(param_1,lVar12 + 1);
80: FUN_0014a8b0(param_1);
81: goto LAB_0014c1e8;
82: }
83: }
84: lVar1 = lVar12 + 1;
85: lVar12 = lVar12 + 3;
86: lVar14 = lVar14 + 1;
87: FUN_0014a8b0(param_1,lVar1);
88: } while( true );
89: }
90: LAB_0014c1fb:
91: if (iVar11 <= iVar8) {
92: FUN_0014ac60(param_1,(long)(iVar11 * 3 + -3) + *(long *)(lVar4 + 0xe8 + (long)iVar3 * 8));
93: }
94: return 1;
95: LAB_0014c0c0:
96: piVar10 = piVar10 + -1;
97: iVar13 = iVar13 + -1;
98: if (iVar13 == 0) goto LAB_0014c2a8;
99: goto LAB_0014c0ce;
100: LAB_0014c2a8:
101: iStack84 = 0;
102: goto LAB_0014c11f;
103: code_r0x0014c1b1:
104: if (uVar9 >> 1 == 0) {
105: FUN_0014ac60(param_1,lVar12 + 1);
106: FUN_0014ac60(param_1);
107: }
108: else {
109: LAB_0014c270:
110: FUN_0014b010(param_1,lVar12 + 2,uVar9 & 1);
111: }
112: LAB_0014c1e8:
113: iVar11 = (int)lVar14 + 1;
114: if (iVar13 < iVar11) goto code_r0x0014c1f5;
115: goto LAB_0014c148;
116: code_r0x0014c1f5:
117: iVar8 = *(int *)(param_1 + 0x1a0);
118: goto LAB_0014c1fb;
119: }
120: 
