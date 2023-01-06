1: 
2: void FUN_001354d0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: short sVar3;
8: short sVar4;
9: int *piVar5;
10: int *piVar6;
11: short *psVar7;
12: short *psVar8;
13: undefined *puVar9;
14: long lVar10;
15: short *psVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: int aiStack168 [5];
22: int aiStack148 [5];
23: int aiStack128 [5];
24: int aiStack108 [5];
25: int aiStack88 [5];
26: int aiStack68 [5];
27: 
28: lVar14 = *(long *)(param_1 + 0x1a8) + 0x80;
29: psVar7 = param_3;
30: piVar5 = aiStack168;
31: psVar11 = *(short **)(param_2 + 0x58);
32: do {
33: psVar8 = psVar7 + 1;
34: sVar2 = psVar7[8];
35: sVar3 = psVar7[0x18];
36: lVar12 = (long)((int)*psVar7 * (int)*psVar11) * 0x2000 + 0x400;
37: lVar10 = (long)((int)psVar7[0x10] * (int)psVar11[0x10]) +
38: (long)((int)psVar7[0x20] * (int)psVar11[0x20]);
39: lVar15 = (long)((int)psVar7[0x10] * (int)psVar11[0x10]) -
40: (long)((int)psVar7[0x20] * (int)psVar11[0x20]);
41: lVar13 = lVar12 + lVar15 * 0xb50;
42: lVar1 = lVar13 + lVar10 * 0x194c;
43: lVar13 = lVar13 + lVar10 * -0x194c;
44: sVar4 = psVar11[8];
45: piVar5[10] = (int)(lVar12 + lVar15 * -0x2d40 >> 0xb);
46: lVar10 = ((long)((int)sVar2 * (int)sVar4) + (long)((int)sVar3 * (int)psVar11[0x18])) * 0x1a9a;
47: lVar12 = (long)((int)sVar2 * (int)sVar4) * 0x1071 + lVar10;
48: lVar10 = (long)((int)sVar3 * (int)psVar11[0x18]) * -0x45a4 + lVar10;
49: piVar5[0x14] = (int)(lVar1 - lVar12 >> 0xb);
50: *piVar5 = (int)(lVar1 + lVar12 >> 0xb);
51: piVar5[0xf] = (int)(lVar13 - lVar10 >> 0xb);
52: piVar5[5] = (int)(lVar13 + lVar10 >> 0xb);
53: psVar7 = psVar8;
54: piVar5 = piVar5 + 1;
55: psVar11 = psVar11 + 1;
56: } while (psVar8 != param_3 + 5);
57: piVar5 = aiStack168;
58: do {
59: piVar6 = piVar5 + 5;
60: puVar9 = (undefined *)((ulong)param_5 + *param_4);
61: param_4 = param_4 + 1;
62: lVar10 = (long)piVar5[2] + (long)piVar5[4];
63: lVar12 = (long)piVar5[2] - (long)piVar5[4];
64: lVar15 = ((long)*piVar5 + 0x10) * 0x2000;
65: lVar13 = lVar15 + lVar12 * 0xb50;
66: lVar1 = lVar13 + lVar10 * 0x194c;
67: lVar13 = lVar13 + lVar10 * -0x194c;
68: lVar10 = ((long)piVar5[1] + (long)piVar5[3]) * 0x1a9a;
69: lVar16 = (long)piVar5[1] * 0x1071 + lVar10;
70: lVar10 = (long)piVar5[3] * -0x45a4 + lVar10;
71: *puVar9 = *(undefined *)(lVar14 + (ulong)((uint)(lVar1 + lVar16 >> 0x12) & 0x3ff));
72: puVar9[4] = *(undefined *)(lVar14 + (ulong)((uint)(lVar1 - lVar16 >> 0x12) & 0x3ff));
73: puVar9[1] = *(undefined *)(lVar14 + (ulong)((uint)(lVar13 + lVar10 >> 0x12) & 0x3ff));
74: puVar9[3] = *(undefined *)(lVar14 + (ulong)((uint)(lVar13 - lVar10 >> 0x12) & 0x3ff));
75: puVar9[2] = *(undefined *)(lVar14 + (ulong)((uint)(lVar15 + lVar12 * -0x2d40 >> 0x12) & 0x3ff));
76: piVar5 = piVar6;
77: } while (piVar6 != aiStack68);
78: return;
79: }
80: 
