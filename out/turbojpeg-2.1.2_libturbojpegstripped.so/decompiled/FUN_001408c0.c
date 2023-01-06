1: 
2: void FUN_001408c0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: short *psVar6;
11: short *psVar7;
12: int *piVar8;
13: long lVar9;
14: short *psVar10;
15: long lVar11;
16: undefined *puVar12;
17: int iVar13;
18: int *piVar14;
19: int iVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: long lVar20;
25: long in_FS_OFFSET;
26: int aiStack216 [6];
27: int aiStack192 [6];
28: int aiStack168 [6];
29: int aiStack144 [6];
30: int aiStack120 [6];
31: int aiStack96 [6];
32: int aiStack72 [2];
33: long lStack64;
34: 
35: piVar14 = aiStack216;
36: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
37: lVar19 = *(long *)(param_1 + 0x1a8) + 0x80;
38: psVar6 = param_3;
39: piVar8 = piVar14;
40: psVar10 = *(short **)(param_2 + 0x58);
41: do {
42: psVar7 = psVar6 + 1;
43: lVar5 = (long)((int)*psVar6 * (int)*psVar10) * 0x2000 + 0x400;
44: lVar11 = lVar5 + (long)((int)psVar6[0x20] * (int)psVar10[0x20]) * 0x16a1;
45: lVar1 = lVar11 + (long)((int)psVar6[0x10] * (int)psVar10[0x10]) * 0x2731;
46: lVar11 = lVar11 + (long)((int)psVar6[0x10] * (int)psVar10[0x10]) * -0x2731;
47: iVar4 = (int)psVar6[8] * (int)psVar10[8];
48: iVar15 = (int)psVar6[0x18] * (int)psVar10[0x18];
49: iVar13 = (int)psVar6[0x28] * (int)psVar10[0x28];
50: iVar3 = (iVar4 - iVar15) - iVar13;
51: lVar17 = ((long)iVar4 + (long)iVar13) * 0xbb6;
52: iVar2 = (int)(lVar5 + (long)((int)psVar6[0x20] * (int)psVar10[0x20]) * -0x2d42 >> 0xb);
53: piVar8[0x18] = iVar2 + iVar3 * -4;
54: piVar8[6] = iVar3 * 4 + iVar2;
55: lVar5 = ((long)iVar13 - (long)iVar15) * 0x2000 + lVar17;
56: lVar17 = ((long)iVar4 + (long)iVar15) * 0x2000 + lVar17;
57: *piVar8 = (int)(lVar1 + lVar17 >> 0xb);
58: piVar8[0x1e] = (int)(lVar1 - lVar17 >> 0xb);
59: piVar8[0xc] = (int)(lVar11 + lVar5 >> 0xb);
60: piVar8[0x12] = (int)(lVar11 - lVar5 >> 0xb);
61: psVar6 = psVar7;
62: piVar8 = piVar8 + 1;
63: psVar10 = psVar10 + 1;
64: } while (psVar7 != param_3 + 6);
65: do {
66: lVar17 = (long)piVar14[1];
67: lVar18 = (long)piVar14[5];
68: lVar20 = (long)piVar14[3];
69: lVar5 = ((long)*piVar14 + 0x10) * 0x2000;
70: puVar12 = (undefined *)(*param_4 + (ulong)param_5);
71: lVar11 = lVar5 + (long)piVar14[4] * 0x16a1;
72: lVar5 = lVar5 + (long)piVar14[4] * -0x2d42;
73: lVar1 = lVar11 + (long)piVar14[2] * 0x2731;
74: lVar11 = lVar11 + (long)piVar14[2] * -0x2731;
75: lVar16 = (lVar17 + lVar18) * 0xbb6;
76: lVar9 = (lVar17 - lVar20) - lVar18;
77: lVar17 = (lVar17 + lVar20) * 0x2000 + lVar16;
78: lVar16 = (lVar18 - lVar20) * 0x2000 + lVar16;
79: *puVar12 = *(undefined *)(lVar19 + (ulong)((uint)(lVar1 + lVar17 >> 0x12) & 0x3ff));
80: puVar12[5] = *(undefined *)(lVar19 + (ulong)((uint)(lVar1 - lVar17 >> 0x12) & 0x3ff));
81: puVar12[1] = *(undefined *)(lVar19 + (ulong)((uint)(lVar5 + lVar9 * 0x2000 >> 0x12) & 0x3ff));
82: puVar12[4] = *(undefined *)(lVar19 + (ulong)((uint)(lVar5 + lVar9 * -0x2000 >> 0x12) & 0x3ff));
83: puVar12[2] = *(undefined *)(lVar19 + (ulong)((uint)(lVar11 + lVar16 >> 0x12) & 0x3ff));
84: piVar14 = piVar14 + 6;
85: param_4 = param_4 + 1;
86: puVar12[3] = *(undefined *)(lVar19 + (ulong)((uint)(lVar11 - lVar16 >> 0x12) & 0x3ff));
87: } while (piVar14 != aiStack72);
88: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
89: return;
90: }
91: /* WARNING: Subroutine does not return */
92: __stack_chk_fail();
93: }
94: 
