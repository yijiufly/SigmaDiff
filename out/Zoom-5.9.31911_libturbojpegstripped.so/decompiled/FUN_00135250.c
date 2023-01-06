1: 
2: void FUN_00135250(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: int iVar3;
8: int *piVar4;
9: int *piVar5;
10: short *psVar6;
11: short *psVar7;
12: short *psVar8;
13: undefined *puVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: int iVar15;
20: int iVar16;
21: long lVar17;
22: int iVar18;
23: long lVar19;
24: long lVar20;
25: int aiStack200 [6];
26: int aiStack176 [6];
27: int aiStack152 [6];
28: int aiStack128 [6];
29: int aiStack104 [6];
30: int aiStack80 [6];
31: int aiStack56 [2];
32: 
33: lVar14 = *(long *)(param_1 + 0x1a8) + 0x80;
34: piVar4 = aiStack200;
35: psVar6 = *(short **)(param_2 + 0x58);
36: psVar7 = param_3;
37: do {
38: psVar8 = psVar7 + 1;
39: lVar12 = (long)((int)*psVar7 * (int)*psVar6) * 0x2000 + 0x400;
40: lVar19 = lVar12 + (long)((int)psVar7[0x20] * (int)psVar6[0x20]) * 0x16a1;
41: lVar1 = lVar19 + (long)((int)psVar7[0x10] * (int)psVar6[0x10]) * 0x2731;
42: lVar19 = lVar19 + (long)((int)psVar7[0x10] * (int)psVar6[0x10]) * -0x2731;
43: iVar15 = (int)psVar7[8] * (int)psVar6[8];
44: iVar18 = (int)psVar7[0x18] * (int)psVar6[0x18];
45: iVar16 = (int)psVar7[0x28] * (int)psVar6[0x28];
46: iVar3 = (iVar15 - iVar18) - iVar16;
47: lVar11 = ((long)iVar15 + (long)iVar16) * 0xbb6;
48: iVar2 = (int)(lVar12 + (long)((int)psVar7[0x20] * (int)psVar6[0x20]) * -0x2d42 >> 0xb);
49: piVar4[0x18] = iVar2 + iVar3 * -4;
50: piVar4[6] = iVar3 * 4 + iVar2;
51: lVar12 = ((long)iVar15 + (long)iVar18) * 0x2000 + lVar11;
52: lVar11 = lVar11 + ((long)iVar16 - (long)iVar18) * 0x2000;
53: *piVar4 = (int)(lVar1 + lVar12 >> 0xb);
54: piVar4[0x1e] = (int)(lVar1 - lVar12 >> 0xb);
55: piVar4[0xc] = (int)(lVar19 + lVar11 >> 0xb);
56: piVar4[0x12] = (int)(lVar19 - lVar11 >> 0xb);
57: piVar4 = piVar4 + 1;
58: psVar6 = psVar6 + 1;
59: psVar7 = psVar8;
60: } while (psVar8 != param_3 + 6);
61: piVar4 = aiStack200;
62: do {
63: lVar11 = (long)piVar4[1];
64: piVar5 = piVar4 + 6;
65: lVar20 = (long)piVar4[3];
66: puVar9 = (undefined *)((ulong)param_5 + *param_4);
67: lVar13 = ((long)*piVar4 + 0x10) * 0x2000;
68: lVar19 = lVar13 + (long)piVar4[4] * 0x16a1;
69: lVar13 = lVar13 + (long)piVar4[4] * -0x2d42;
70: lVar1 = lVar19 + (long)piVar4[2] * 0x2731;
71: lVar19 = lVar19 + (long)piVar4[2] * -0x2731;
72: lVar17 = (long)piVar4[5];
73: lVar12 = (lVar11 - lVar20) - lVar17;
74: lVar10 = (lVar11 + lVar17) * 0xbb6;
75: lVar11 = (lVar11 + lVar20) * 0x2000 + lVar10;
76: lVar10 = lVar10 + (lVar17 - lVar20) * 0x2000;
77: *puVar9 = *(undefined *)(lVar14 + (ulong)((uint)(lVar1 + lVar11 >> 0x12) & 0x3ff));
78: puVar9[5] = *(undefined *)(lVar14 + (ulong)((uint)(lVar1 - lVar11 >> 0x12) & 0x3ff));
79: puVar9[1] = *(undefined *)(lVar14 + (ulong)((uint)(lVar13 + lVar12 * 0x2000 >> 0x12) & 0x3ff));
80: puVar9[4] = *(undefined *)(lVar14 + (ulong)((uint)(lVar13 + lVar12 * -0x2000 >> 0x12) & 0x3ff));
81: puVar9[2] = *(undefined *)(lVar14 + (ulong)((uint)(lVar19 + lVar10 >> 0x12) & 0x3ff));
82: param_4 = param_4 + 1;
83: puVar9[3] = *(undefined *)(lVar14 + (ulong)((uint)(lVar19 - lVar10 >> 0x12) & 0x3ff));
84: piVar4 = piVar5;
85: } while (piVar5 != aiStack56);
86: return;
87: }
88: 
