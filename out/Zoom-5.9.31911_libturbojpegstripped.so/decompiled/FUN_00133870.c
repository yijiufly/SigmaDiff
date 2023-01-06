1: 
2: void FUN_00133870(short *param_1)
3: 
4: {
5: short *psVar1;
6: short *psVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: short sVar6;
11: short sVar7;
12: short sVar8;
13: short sVar9;
14: short sVar10;
15: short sVar11;
16: 
17: psVar1 = param_1;
18: do {
19: psVar2 = psVar1 + 8;
20: sVar9 = psVar1[4];
21: sVar7 = psVar1[7] + *psVar1;
22: sVar8 = psVar1[6] + psVar1[1];
23: sVar5 = *psVar1 - psVar1[7];
24: sVar10 = psVar1[1] - psVar1[6];
25: sVar3 = psVar1[5] + psVar1[2];
26: sVar6 = psVar1[2] - psVar1[5];
27: sVar11 = sVar9 + psVar1[3];
28: sVar4 = sVar11 + sVar7;
29: sVar7 = sVar7 - sVar11;
30: sVar11 = sVar3 + sVar8;
31: psVar1[4] = sVar4 - sVar11;
32: *psVar1 = sVar11 + sVar4;
33: sVar4 = (short)((ulong)((long)((int)(short)(sVar8 - sVar3) + (int)sVar7) * 0xb5) >> 8);
34: psVar1[6] = sVar7 - sVar4;
35: sVar8 = sVar10 + sVar5;
36: sVar9 = psVar1[3] + (sVar6 - sVar9);
37: psVar1[2] = sVar7 + sVar4;
38: sVar11 = (short)((ulong)((long)((int)sVar9 - (int)sVar8) * 0x62) >> 8);
39: sVar4 = (short)((ulong)((long)sVar9 * 0x8b) >> 8) + sVar11;
40: sVar11 = sVar11 + (short)((ulong)((long)sVar8 * 0x14e) >> 8);
41: sVar8 = (short)((ulong)((long)(short)(sVar6 + sVar10) * 0xb5) >> 8);
42: sVar9 = sVar5 + sVar8;
43: sVar5 = sVar5 - sVar8;
44: psVar1[3] = sVar5 - sVar4;
45: psVar1[5] = sVar4 + sVar5;
46: psVar1[7] = sVar9 - sVar11;
47: psVar1[1] = sVar11 + sVar9;
48: psVar1 = psVar2;
49: } while (psVar2 != param_1 + 0x40);
50: psVar1 = param_1;
51: do {
52: psVar2 = psVar1 + 1;
53: sVar9 = psVar1[0x20];
54: sVar7 = psVar1[0x38] + *psVar1;
55: sVar5 = *psVar1 - psVar1[0x38];
56: sVar3 = psVar1[0x30] + psVar1[8];
57: sVar10 = psVar1[8] - psVar1[0x30];
58: sVar6 = psVar1[0x28] + psVar1[0x10];
59: sVar8 = psVar1[0x10] - psVar1[0x28];
60: sVar4 = sVar9 + psVar1[0x18];
61: sVar11 = sVar4 + sVar7;
62: sVar7 = sVar7 - sVar4;
63: sVar4 = sVar6 + sVar3;
64: psVar1[0x20] = sVar11 - sVar4;
65: *psVar1 = sVar4 + sVar11;
66: sVar4 = (short)((ulong)((long)((int)(short)(sVar3 - sVar6) + (int)sVar7) * 0xb5) >> 8);
67: psVar1[0x30] = sVar7 - sVar4;
68: sVar6 = sVar10 + sVar5;
69: sVar9 = psVar1[0x18] + (sVar8 - sVar9);
70: psVar1[0x10] = sVar7 + sVar4;
71: sVar11 = (short)((ulong)((long)((int)sVar9 - (int)sVar6) * 0x62) >> 8);
72: sVar4 = (short)((ulong)((long)sVar9 * 0x8b) >> 8) + sVar11;
73: sVar11 = sVar11 + (short)((ulong)((long)sVar6 * 0x14e) >> 8);
74: sVar8 = (short)((ulong)((long)(short)(sVar8 + sVar10) * 0xb5) >> 8);
75: sVar9 = sVar5 + sVar8;
76: sVar5 = sVar5 - sVar8;
77: psVar1[0x18] = sVar5 - sVar4;
78: psVar1[0x28] = sVar4 + sVar5;
79: psVar1[0x38] = sVar9 - sVar11;
80: psVar1[8] = sVar11 + sVar9;
81: psVar1 = psVar2;
82: } while (psVar2 != param_1 + 8);
83: return;
84: }
85: 
