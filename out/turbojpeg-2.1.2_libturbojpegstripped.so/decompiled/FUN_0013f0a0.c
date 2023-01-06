1: 
2: void FUN_0013f0a0(short *param_1)
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
20: sVar6 = psVar1[4];
21: sVar5 = *psVar1 + psVar1[7];
22: sVar4 = *psVar1 - psVar1[7];
23: sVar8 = psVar1[1] + psVar1[6];
24: sVar3 = psVar1[1] - psVar1[6];
25: sVar10 = psVar1[2] + psVar1[5];
26: sVar9 = psVar1[2] - psVar1[5];
27: sVar11 = psVar1[3] + sVar6;
28: sVar7 = sVar5 + sVar11;
29: sVar5 = sVar5 - sVar11;
30: sVar11 = sVar8 + sVar10;
31: psVar1[4] = sVar7 - sVar11;
32: *psVar1 = sVar7 + sVar11;
33: sVar7 = (short)((ulong)((long)((int)(short)(sVar8 - sVar10) + (int)sVar5) * 0xb5) >> 8);
34: psVar1[6] = sVar5 - sVar7;
35: sVar8 = sVar4 + sVar3;
36: sVar6 = psVar1[3] + (sVar9 - sVar6);
37: psVar1[2] = sVar5 + sVar7;
38: sVar11 = (short)((ulong)((long)((int)sVar6 - (int)sVar8) * 0x62) >> 8);
39: sVar7 = (short)((ulong)((long)sVar6 * 0x8b) >> 8) + sVar11;
40: sVar3 = (short)((ulong)((long)(short)(sVar3 + sVar9) * 0xb5) >> 8);
41: sVar6 = sVar4 + sVar3;
42: sVar4 = sVar4 - sVar3;
43: psVar1[3] = sVar4 - sVar7;
44: psVar1[5] = sVar7 + sVar4;
45: sVar11 = (short)((ulong)((long)sVar8 * 0x14e) >> 8) + sVar11;
46: psVar1[7] = sVar6 - sVar11;
47: psVar1[1] = sVar11 + sVar6;
48: psVar1 = psVar2;
49: } while (psVar2 != param_1 + 0x40);
50: psVar1 = param_1;
51: do {
52: psVar2 = psVar1 + 1;
53: sVar10 = *psVar1 + psVar1[0x38];
54: sVar4 = *psVar1 - psVar1[0x38];
55: sVar3 = psVar1[8] + psVar1[0x30];
56: sVar8 = psVar1[8] - psVar1[0x30];
57: sVar9 = psVar1[0x10] + psVar1[0x28];
58: sVar5 = psVar1[0x10] - psVar1[0x28];
59: sVar6 = psVar1[0x20];
60: sVar11 = psVar1[0x18] + sVar6;
61: sVar7 = sVar10 + sVar11;
62: sVar10 = sVar10 - sVar11;
63: sVar11 = sVar3 + sVar9;
64: psVar1[0x20] = sVar7 - sVar11;
65: *psVar1 = sVar7 + sVar11;
66: sVar7 = (short)((ulong)((long)((int)(short)(sVar3 - sVar9) + (int)sVar10) * 0xb5) >> 8);
67: psVar1[0x30] = sVar10 - sVar7;
68: psVar1[0x10] = sVar10 + sVar7;
69: sVar7 = (sVar5 - sVar6) + psVar1[0x18];
70: sVar9 = sVar4 + sVar8;
71: sVar11 = (short)((ulong)((long)((int)sVar7 - (int)sVar9) * 0x62) >> 8);
72: sVar7 = (short)((ulong)((long)sVar7 * 0x8b) >> 8) + sVar11;
73: sVar3 = (short)((ulong)((long)(short)(sVar5 + sVar8) * 0xb5) >> 8);
74: sVar6 = sVar4 + sVar3;
75: sVar4 = sVar4 - sVar3;
76: psVar1[0x18] = sVar4 - sVar7;
77: psVar1[0x28] = sVar7 + sVar4;
78: sVar11 = (short)((ulong)((long)sVar9 * 0x14e) >> 8) + sVar11;
79: psVar1[0x38] = sVar6 - sVar11;
80: psVar1[8] = sVar11 + sVar6;
81: psVar1 = psVar2;
82: } while (psVar2 != param_1 + 8);
83: return;
84: }
85: 
