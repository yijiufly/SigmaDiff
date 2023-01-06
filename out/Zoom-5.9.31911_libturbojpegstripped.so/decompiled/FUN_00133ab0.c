1: 
2: void FUN_00133ab0(short *param_1)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: short sVar5;
10: short sVar6;
11: short *psVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: short *psVar13;
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
28: lVar8 = (long)((int)psVar7[1] - (int)psVar7[6]);
29: iVar3 = (int)psVar7[2] + (int)psVar7[5];
30: lVar12 = (long)((int)psVar7[2] - (int)psVar7[5]);
31: iVar4 = (int)psVar7[3] + (int)psVar7[4];
32: lVar14 = (long)((int)psVar7[3] - (int)psVar7[4]);
33: sVar5 = (short)iVar1 + (short)iVar4;
34: lVar15 = (long)iVar1 - (long)iVar4;
35: sVar6 = (short)iVar2 + (short)iVar3;
36: lVar10 = (long)iVar2 - (long)iVar3;
37: lVar16 = (lVar10 + lVar15) * 0x1151;
38: psVar7[4] = (sVar5 - sVar6) * 4;
39: *psVar7 = (sVar5 + sVar6) * 4;
40: lVar11 = (lVar12 + lVar8) * -0x5203;
41: psVar7[2] = (short)(lVar16 + 0x400 + lVar15 * 0x187e >> 0xb);
42: psVar7[6] = (short)(lVar16 + 0x400 + lVar10 * -0x3b21 >> 0xb);
43: lVar16 = (lVar14 + lVar9) * -0x1ccd;
44: lVar15 = (lVar14 + lVar8 + lVar12 + lVar9) * 0x25a1;
45: lVar10 = (lVar14 + lVar8) * -0x3ec5 + lVar15;
46: lVar15 = (lVar12 + lVar9) * -0xc7c + lVar15;
47: psVar7[7] = (short)(lVar10 + 0x400 + lVar14 * 0x98e + lVar16 >> 0xb);
48: psVar7[1] = (short)(lVar15 + 0x400 + lVar16 + lVar9 * 0x300b >> 0xb);
49: psVar7[5] = (short)(lVar15 + 0x400 + lVar12 * 0x41b3 + lVar11 >> 0xb);
50: psVar7[3] = (short)(lVar10 + 0x400 + lVar11 + lVar8 * 0x6254 >> 0xb);
51: psVar7 = psVar7 + 8;
52: } while (psVar7 != param_1 + 0x40);
53: psVar7 = param_1;
54: do {
55: lVar10 = (long)((int)*psVar7 - (int)psVar7[0x38]);
56: lVar14 = (long)((int)*psVar7 + (int)psVar7[0x38]);
57: lVar12 = (long)((int)psVar7[8] - (int)psVar7[0x30]);
58: lVar17 = (long)((int)psVar7[8] + (int)psVar7[0x30]);
59: lVar11 = (long)((int)psVar7[0x10] - (int)psVar7[0x28]);
60: lVar16 = (long)((int)psVar7[0x10] + (int)psVar7[0x28]);
61: lVar15 = (long)((int)psVar7[0x18] - (int)psVar7[0x20]);
62: lVar9 = (long)((int)psVar7[0x18] + (int)psVar7[0x20]);
63: lVar8 = lVar14 + lVar9;
64: lVar14 = lVar14 - lVar9;
65: lVar9 = lVar17 + lVar16;
66: lVar17 = lVar17 - lVar16;
67: *psVar7 = (short)(lVar8 + 2 + lVar9 >> 2);
68: psVar7[0x20] = (short)((lVar8 - lVar9) + 2 >> 2);
69: lVar8 = (lVar17 + lVar14) * 0x1151;
70: psVar7[0x10] = (short)(lVar8 + 0x4000 + lVar14 * 0x187e >> 0xf);
71: psVar7[0x30] = (short)(lVar8 + 0x4000 + lVar17 * -0x3b21 >> 0xf);
72: lVar14 = (lVar15 + lVar10) * -0x1ccd;
73: lVar8 = (lVar11 + lVar12) * -0x5203;
74: lVar9 = (lVar15 + lVar12 + lVar11 + lVar10) * 0x25a1;
75: lVar16 = (lVar15 + lVar12) * -0x3ec5 + lVar9;
76: lVar9 = (lVar11 + lVar10) * -0xc7c + lVar9;
77: psVar7[0x38] = (short)(lVar16 + 0x4000 + lVar15 * 0x98e + lVar14 >> 0xf);
78: psVar7[0x28] = (short)(lVar9 + 0x4000 + lVar11 * 0x41b3 + lVar8 >> 0xf);
79: psVar7[0x18] = (short)(lVar16 + 0x4000 + lVar8 + lVar12 * 0x6254 >> 0xf);
80: psVar13 = psVar7 + 1;
81: psVar7[8] = (short)(lVar9 + 0x4000 + lVar14 + lVar10 * 0x300b >> 0xf);
82: psVar7 = psVar13;
83: } while (psVar13 != param_1 + 8);
84: return;
85: }
86: 
