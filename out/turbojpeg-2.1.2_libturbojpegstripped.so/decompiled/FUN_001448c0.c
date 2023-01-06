1: 
2: void FUN_001448c0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: undefined uVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: long lVar6;
11: short *psVar7;
12: int *piVar8;
13: int *piVar9;
14: long lVar10;
15: long lVar11;
16: undefined *puVar12;
17: long lVar13;
18: long lVar14;
19: int iVar15;
20: long lVar16;
21: long lVar17;
22: long in_FS_OFFSET;
23: int aiStack200 [8];
24: int aiStack168 [8];
25: int aiStack136 [8];
26: int aiStack104 [8];
27: int aiStack72 [2];
28: long lStack64;
29: 
30: iVar15 = 8;
31: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
32: lVar16 = *(long *)(param_1 + 0x1a8) + 0x80;
33: psVar7 = *(short **)(param_2 + 0x58);
34: piVar8 = aiStack200;
35: do {
36: if (iVar15 != 4) {
37: if ((((param_3[8] == 0) && (param_3[0x10] == 0)) && (param_3[0x18] == 0)) &&
38: (((param_3[0x28] == 0 && (param_3[0x30] == 0)) && (param_3[0x38] == 0)))) {
39: iVar5 = (int)((long)((int)*param_3 * (int)*psVar7) << 2);
40: *piVar8 = iVar5;
41: piVar8[8] = iVar5;
42: piVar8[0x10] = iVar5;
43: piVar8[0x18] = iVar5;
44: }
45: else {
46: lVar6 = (long)((int)*param_3 * (int)*psVar7) * 0x4000;
47: lVar10 = (long)((int)psVar7[0x10] * (int)param_3[0x10]) * 0x3b21 +
48: (long)((int)psVar7[0x30] * (int)param_3[0x30]) * -0x187e;
49: lVar1 = lVar6 + lVar10;
50: lVar6 = lVar6 - lVar10;
51: lVar11 = (long)((int)param_3[0x38] * (int)psVar7[0x38]);
52: lVar17 = (long)((int)param_3[0x28] * (int)psVar7[0x28]);
53: lVar10 = (long)((int)param_3[0x18] * (int)psVar7[0x18]);
54: lVar14 = (long)((int)param_3[8] * (int)psVar7[8]);
55: lVar13 = lVar11 * -0x6c2 + lVar17 * 0x2e75 + lVar10 * -0x4587 + lVar14 * 0x21f9;
56: lVar10 = lVar17 * -0x133e + lVar11 * -0x1050 + lVar10 * 0x1ccd + lVar14 * 0x5203;
57: *piVar8 = (int)(lVar1 + 0x800 + lVar10 >> 0xc);
58: piVar8[0x18] = (int)((lVar1 - lVar10) + 0x800 >> 0xc);
59: piVar8[8] = (int)(lVar6 + 0x800 + lVar13 >> 0xc);
60: piVar8[0x10] = (int)((lVar6 - lVar13) + 0x800 >> 0xc);
61: }
62: if (iVar15 == 1) {
63: piVar8 = aiStack200;
64: do {
65: iVar15 = piVar8[1];
66: piVar9 = piVar8 + 8;
67: iVar5 = piVar8[7];
68: iVar3 = piVar8[5];
69: iVar4 = piVar8[3];
70: puVar12 = (undefined *)(*param_4 + (ulong)param_5);
71: if (((iVar15 == 0) && (piVar8[2] == 0)) &&
72: ((iVar4 == 0 && (((iVar3 == 0 && (piVar8[6] == 0)) && (iVar5 == 0)))))) {
73: uVar2 = *(undefined *)(lVar16 + (ulong)((uint)((long)*piVar8 + 0x10 >> 5) & 0x3ff));
74: *puVar12 = uVar2;
75: puVar12[1] = uVar2;
76: puVar12[2] = uVar2;
77: puVar12[3] = uVar2;
78: }
79: else {
80: lVar10 = (long)*piVar8 * 0x4000;
81: lVar6 = (long)piVar8[2] * 0x3b21 + (long)piVar8[6] * -0x187e;
82: lVar1 = lVar10 + lVar6;
83: lVar10 = lVar10 - lVar6;
84: lVar11 = (long)iVar5 * -0x6c2 + (long)iVar3 * 0x2e75 + (long)iVar4 * -0x4587 +
85: (long)iVar15 * 0x21f9;
86: lVar6 = (long)iVar3 * -0x133e + (long)iVar5 * -0x1050 + (long)iVar4 * 0x1ccd +
87: (long)iVar15 * 0x5203;
88: *puVar12 = *(undefined *)
89: (lVar16 + (ulong)((uint)(lVar1 + 0x40000 + lVar6 >> 0x13) & 0x3ff));
90: puVar12[3] = *(undefined *)
91: (lVar16 + (ulong)(((int)lVar1 - (int)lVar6) * 8 + 0x200000U >> 0x16));
92: puVar12[1] = *(undefined *)
93: (lVar16 + (ulong)((uint)(lVar10 + 0x40000 + lVar11 >> 0x13) & 0x3ff));
94: puVar12[2] = *(undefined *)
95: (lVar16 + (ulong)(((int)lVar10 - (int)lVar11) * 8 + 0x200000U >> 0x16));
96: }
97: param_4 = param_4 + 1;
98: piVar8 = piVar9;
99: } while (piVar9 != aiStack72);
100: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
101: /* WARNING: Subroutine does not return */
102: __stack_chk_fail();
103: }
104: return;
105: }
106: }
107: iVar15 = iVar15 + -1;
108: param_3 = param_3 + 1;
109: psVar7 = psVar7 + 1;
110: piVar8 = piVar8 + 1;
111: } while( true );
112: }
113: 
