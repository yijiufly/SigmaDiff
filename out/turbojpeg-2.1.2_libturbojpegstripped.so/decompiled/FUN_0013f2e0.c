1: 
2: void FUN_0013f2e0(short *param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: short sVar5;
10: short sVar6;
11: short *psVar7;
12: short *psVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: 
23: psVar7 = param_1;
24: do {
25: iVar1 = (int)*psVar7 + (int)psVar7[7];
26: lVar9 = (long)((int)*psVar7 - (int)psVar7[7]);
27: iVar2 = (int)psVar7[1] + (int)psVar7[6];
28: lVar12 = (long)((int)psVar7[1] - (int)psVar7[6]);
29: iVar3 = (int)psVar7[2] + (int)psVar7[5];
30: lVar13 = (long)((int)psVar7[2] - (int)psVar7[5]);
31: iVar4 = (int)psVar7[3] + (int)psVar7[4];
32: lVar10 = (long)((int)psVar7[3] - (int)psVar7[4]);
33: sVar5 = (short)iVar1 + (short)iVar4;
34: lVar11 = (long)iVar1 - (long)iVar4;
35: sVar6 = (short)iVar2 + (short)iVar3;
36: lVar15 = (long)iVar2 - (long)iVar3;
37: psVar7[4] = (sVar5 - sVar6) * 4;
38: *psVar7 = (sVar5 + sVar6) * 4;
39: lVar14 = (lVar11 + lVar15) * 0x1151;
40: psVar7[2] = (short)(lVar14 + 0x400 + lVar11 * 0x187e >> 0xb);
41: psVar7[6] = (short)(lVar14 + 0x400 + lVar15 * -0x3b21 >> 0xb);
42: lVar16 = (lVar9 + lVar10) * -0x1ccd;
43: lVar15 = (lVar12 + lVar10 + lVar9 + lVar13) * 0x25a1;
44: lVar11 = (lVar12 + lVar10) * -0x3ec5 + lVar15;
45: lVar14 = (lVar12 + lVar13) * -0x5203;
46: lVar15 = lVar15 + (lVar9 + lVar13) * -0xc7c;
47: psVar7[7] = (short)(lVar11 + 0x400 + lVar10 * 0x98e + lVar16 >> 0xb);
48: psVar7[5] = (short)(lVar15 + 0x400 + lVar13 * 0x41b3 + lVar14 >> 0xb);
49: psVar7[3] = (short)(lVar11 + 0x400 + lVar12 * 0x6254 + lVar14 >> 0xb);
50: psVar8 = psVar7 + 8;
51: psVar7[1] = (short)(lVar15 + 0x400 + lVar9 * 0x300b + lVar16 >> 0xb);
52: psVar7 = psVar8;
53: } while (psVar8 != param_1 + 0x40);
54: psVar7 = param_1;
55: do {
56: lVar11 = (long)((int)*psVar7 - (int)psVar7[0x38]);
57: lVar17 = (long)((int)*psVar7 + (int)psVar7[0x38]);
58: lVar12 = (long)((int)psVar7[8] - (int)psVar7[0x30]);
59: lVar16 = (long)((int)psVar7[8] + (int)psVar7[0x30]);
60: lVar14 = (long)((int)psVar7[0x10] - (int)psVar7[0x28]);
61: lVar13 = (long)((int)psVar7[0x10] + (int)psVar7[0x28]);
62: lVar15 = (long)((int)psVar7[0x18] - (int)psVar7[0x20]);
63: lVar10 = (long)((int)psVar7[0x18] + (int)psVar7[0x20]);
64: lVar9 = lVar17 + lVar10;
65: lVar17 = lVar17 - lVar10;
66: lVar10 = lVar16 + lVar13;
67: lVar16 = lVar16 - lVar13;
68: psVar7[0x20] = (short)((lVar9 - lVar10) + 2 >> 2);
69: *psVar7 = (short)(lVar9 + 2 + lVar10 >> 2);
70: lVar9 = (lVar17 + lVar16) * 0x1151;
71: psVar7[0x10] = (short)(lVar9 + 0x4000 + lVar17 * 0x187e >> 0xf);
72: psVar7[0x30] = (short)(lVar9 + 0x4000 + lVar16 * -0x3b21 >> 0xf);
73: lVar9 = (lVar12 + lVar14) * -0x5203;
74: lVar10 = (lVar12 + lVar15 + lVar11 + lVar14) * 0x25a1;
75: lVar13 = (lVar11 + lVar15) * -0x1ccd;
76: lVar16 = (lVar12 + lVar15) * -0x3ec5 + lVar10;
77: lVar10 = lVar10 + (lVar11 + lVar14) * -0xc7c;
78: psVar7[0x38] = (short)(lVar16 + 0x4000 + lVar15 * 0x98e + lVar13 >> 0xf);
79: psVar7[0x28] = (short)(lVar10 + 0x4000 + lVar14 * 0x41b3 + lVar9 >> 0xf);
80: psVar7[0x18] = (short)(lVar16 + 0x4000 + lVar12 * 0x6254 + lVar9 >> 0xf);
81: psVar8 = psVar7 + 1;
82: psVar7[8] = (short)(lVar10 + 0x4000 + lVar11 * 0x300b + lVar13 >> 0xf);
83: psVar7 = psVar8;
84: } while (psVar8 != param_1 + 8);
85: return;
86: }
87: 
