1: 
2: void FUN_001356e0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: short *psVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: ulong uVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: undefined *puVar18;
23: long lVar19;
24: 
25: uVar10 = (ulong)param_5;
26: psVar6 = *(short **)(param_2 + 0x58);
27: lVar7 = *(long *)(param_1 + 0x1a8);
28: sVar2 = param_3[0x10];
29: sVar3 = psVar6[8];
30: sVar4 = psVar6[0x10];
31: sVar5 = param_3[8];
32: lVar15 = (long)((int)*param_3 * (int)*psVar6) * 0x2000 + 0x400;
33: lVar1 = lVar15 + (long)((int)sVar2 * (int)sVar4) * 0x16a1;
34: lVar11 = (long)((int)param_3[1] * (int)psVar6[1]) * 0x2000 + 0x400;
35: lVar8 = lVar11 + (long)((int)param_3[0x11] * (int)psVar6[0x11]) * 0x16a1;
36: lVar12 = (long)(int)(lVar11 + (long)((int)param_3[0x11] * (int)psVar6[0x11]) * -0x2d42 >> 0xb);
37: lVar11 = (long)(int)(lVar8 + (long)((int)param_3[9] * (int)psVar6[9]) * -0x2731 >> 0xb);
38: lVar17 = (long)(int)(lVar8 + (long)((int)param_3[9] * (int)psVar6[9]) * 0x2731 >> 0xb);
39: lVar13 = (long)((int)param_3[2] * (int)psVar6[2]) * 0x2000 + 0x400;
40: lVar8 = lVar13 + (long)((int)param_3[0x12] * (int)psVar6[0x12]) * 0x16a1;
41: lVar19 = (long)(int)(lVar8 + (long)((int)param_3[10] * (int)psVar6[10]) * 0x2731 >> 0xb);
42: lVar9 = ((long)(int)(lVar1 + (long)((int)sVar5 * (int)sVar3) * 0x2731 >> 0xb) + 0x10) * 0x2000;
43: puVar18 = (undefined *)(uVar10 + *param_4);
44: lVar14 = (long)(int)(lVar13 + (long)((int)param_3[0x12] * (int)psVar6[0x12]) * -0x2d42 >> 0xb);
45: lVar16 = (long)(int)(lVar8 + (long)((int)param_3[10] * (int)psVar6[10]) * -0x2731 >> 0xb);
46: lVar8 = lVar9 + lVar19 * 0x16a1;
47: *puVar18 = *(undefined *)(lVar7 + 0x80 + (ulong)((uint)(lVar8 + lVar17 * 0x2731 >> 0x12) & 0x3ff))
48: ;
49: lVar13 = ((long)(int)(lVar15 + (long)((int)sVar2 * (int)sVar4) * -0x2d42 >> 0xb) + 0x10) * 0x2000;
50: puVar18[2] = *(undefined *)
51: (lVar7 + 0x80 + (ulong)((uint)(lVar8 + lVar17 * -0x2731 >> 0x12) & 0x3ff));
52: lVar8 = lVar13 + lVar14 * 0x16a1;
53: puVar18[1] = *(undefined *)
54: (lVar7 + 0x80 + (ulong)((uint)(lVar9 + lVar19 * -0x2d42 >> 0x12) & 0x3ff));
55: puVar18 = (undefined *)(uVar10 + param_4[1]);
56: *puVar18 = *(undefined *)(lVar7 + 0x80 + (ulong)((uint)(lVar8 + lVar12 * 0x2731 >> 0x12) & 0x3ff))
57: ;
58: puVar18[2] = *(undefined *)
59: (lVar7 + 0x80 + (ulong)((uint)(lVar8 + lVar12 * -0x2731 >> 0x12) & 0x3ff));
60: puVar18[1] = *(undefined *)
61: (lVar7 + 0x80 + (ulong)((uint)(lVar13 + lVar14 * -0x2d42 >> 0x12) & 0x3ff));
62: puVar18 = (undefined *)(uVar10 + param_4[2]);
63: lVar8 = ((long)(int)(lVar1 + (long)((int)sVar5 * (int)sVar3) * -0x2731 >> 0xb) + 0x10) * 0x2000;
64: lVar1 = lVar8 + lVar16 * 0x16a1;
65: *puVar18 = *(undefined *)(lVar7 + 0x80 + (ulong)((uint)(lVar1 + lVar11 * 0x2731 >> 0x12) & 0x3ff))
66: ;
67: puVar18[2] = *(undefined *)
68: (lVar7 + 0x80 + (ulong)((uint)(lVar1 + lVar11 * -0x2731 >> 0x12) & 0x3ff));
69: puVar18[1] = *(undefined *)
70: (lVar7 + 0x80 + (ulong)((uint)(lVar8 + lVar16 * -0x2d42 >> 0x12) & 0x3ff));
71: return;
72: }
73: 
