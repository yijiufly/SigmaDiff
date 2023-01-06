1: 
2: undefined8 FUN_0014bc50(long param_1,long *param_2)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: uint uVar6;
11: int iVar7;
12: uint uVar8;
13: long lVar9;
14: byte bVar10;
15: int *piVar11;
16: int iVar12;
17: long lVar13;
18: long lVar14;
19: int iStack80;
20: 
21: lVar4 = *(long *)(param_1 + 0x1f0);
22: if (*(int *)(param_1 + 0x118) != 0) {
23: iVar12 = *(int *)(lVar4 + 0x60);
24: if (iVar12 == 0) {
25: FUN_0014b810();
26: iVar12 = *(int *)(param_1 + 0x118);
27: *(uint *)(lVar4 + 100) = *(int *)(lVar4 + 100) + 1U & 7;
28: }
29: *(int *)(lVar4 + 0x60) = iVar12 + -1;
30: }
31: iVar12 = *(int *)(param_1 + 0x1a0);
32: lVar5 = *param_2;
33: iVar3 = *(int *)(*(long *)(param_1 + 0x148) + 0x18);
34: iStack80 = iVar12;
35: if (0 < iVar12) {
36: piVar11 = (int *)(&DAT_0018f100 + (long)iVar12 * 4);
37: do {
38: sVar2 = *(short *)(lVar5 + (long)*piVar11 * 2);
39: iVar7 = (int)sVar2;
40: if (sVar2 < 0) {
41: iVar7 = -iVar7;
42: }
43: if (iVar7 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f) != 0) break;
44: piVar11 = piVar11 + -1;
45: iStack80 = iStack80 + -1;
46: } while (iStack80 != 0);
47: }
48: iVar7 = *(int *)(param_1 + 0x19c);
49: if (iVar7 <= iStack80) {
50: lVar1 = lVar4 + (long)iVar3 * 8;
51: LAB_0014bd38:
52: lVar14 = (long)iVar7;
53: lVar9 = (long)(iVar7 * 3 + -3) + *(long *)(lVar1 + 0xe8);
54: FUN_0014a8b0(param_1,lVar9);
55: do {
56: iVar12 = (int)*(short *)(lVar5 + (long)*(int *)(&DAT_0018f100 + lVar14 * 4) * 2);
57: bVar10 = (byte)*(undefined4 *)(param_1 + 0x1a8);
58: if (iVar12 < 0) {
59: iVar12 = -iVar12 >> (bVar10 & 0x1f);
60: if (iVar12 != 0) goto code_r0x0014bda5;
61: }
62: else {
63: iVar12 = iVar12 >> (bVar10 & 0x1f);
64: if (iVar12 != 0) {
65: FUN_0014ac60(param_1,lVar9 + 1);
66: FUN_0014a8b0(param_1,lVar4 + 0x168);
67: goto joined_r0x0014be53;
68: }
69: }
70: lVar13 = lVar9 + 1;
71: lVar9 = lVar9 + 3;
72: lVar14 = lVar14 + 1;
73: FUN_0014a8b0(param_1,lVar13);
74: } while( true );
75: }
76: LAB_0014bdee:
77: if (iVar7 <= iVar12) {
78: FUN_0014ac60(param_1,(long)(iVar7 * 3 + -3) + *(long *)(lVar4 + 0xe8 + (long)iVar3 * 8));
79: }
80: return 1;
81: code_r0x0014bda5:
82: FUN_0014ac60(param_1,lVar9 + 1);
83: FUN_0014ac60(param_1,lVar4 + 0x168);
84: joined_r0x0014be53:
85: uVar6 = iVar12 - 1;
86: if (uVar6 != 0) {
87: FUN_0014ac60(param_1,lVar9 + 2);
88: if (uVar6 >> 1 != 0) {
89: FUN_0014ac60(param_1,lVar9 + 2);
90: lVar9 = 0xd9;
91: if ((int)lVar14 <= (int)(uint)*(byte *)(param_1 + 0xe0 + (long)iVar3)) {
92: lVar9 = 0xbd;
93: }
94: lVar9 = lVar9 + *(long *)(lVar1 + 0xe8);
95: iVar12 = (int)uVar6 >> 2;
96: if (iVar12 == 0) {
97: FUN_0014a8b0(param_1,lVar9);
98: FUN_0014b010(param_1,lVar9 + 0xe,uVar6 & 1);
99: }
100: else {
101: uVar8 = 2;
102: do {
103: lVar13 = lVar9;
104: uVar8 = uVar8 * 2;
105: FUN_0014ac60(param_1,lVar13);
106: iVar12 = iVar12 >> 1;
107: lVar9 = lVar13 + 1;
108: } while (iVar12 != 0);
109: FUN_0014a8b0(param_1);
110: while (uVar8 = (int)uVar8 >> 1, uVar8 != 0) {
111: FUN_0014b010(param_1,lVar13 + 0xf,(uVar6 & uVar8) != 0);
112: }
113: }
114: goto LAB_0014bdd9;
115: }
116: }
117: FUN_0014a8b0(param_1);
118: LAB_0014bdd9:
119: iVar7 = (int)lVar14 + 1;
120: if (iStack80 < iVar7) goto code_r0x0014bde6;
121: goto LAB_0014bd38;
122: code_r0x0014bde6:
123: iVar12 = *(int *)(param_1 + 0x1a0);
124: goto LAB_0014bdee;
125: }
126: 
