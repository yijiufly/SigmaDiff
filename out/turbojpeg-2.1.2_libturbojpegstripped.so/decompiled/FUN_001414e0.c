1: 
2: void FUN_001414e0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: long lVar1;
6: short sVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: short sVar6;
11: short sVar7;
12: short sVar8;
13: short sVar9;
14: short sVar10;
15: short sVar11;
16: short sVar12;
17: short sVar13;
18: short *psVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: long lVar20;
25: long lVar21;
26: long lVar22;
27: ulong uVar23;
28: long lVar24;
29: long lVar25;
30: undefined *puVar26;
31: int iStack64;
32: int iStack56;
33: 
34: uVar23 = (ulong)param_5;
35: psVar14 = *(short **)(param_2 + 0x58);
36: lVar15 = *(long *)(param_1 + 0x1a8);
37: sVar2 = param_3[9];
38: sVar3 = param_3[0x12];
39: sVar4 = psVar14[0x10];
40: sVar5 = psVar14[8];
41: sVar6 = psVar14[9];
42: puVar26 = (undefined *)(*param_4 + uVar23);
43: sVar7 = param_3[8];
44: lVar1 = (long)((int)*psVar14 * (int)*param_3) * 0x2000 + 0x400;
45: sVar8 = param_3[0x10];
46: sVar9 = psVar14[0x11];
47: lVar21 = (long)((int)param_3[1] * (int)psVar14[1]) * 0x2000 + 0x400;
48: lVar16 = (long)((int)sVar4 * (int)sVar8) * 0x16a1 + lVar1;
49: sVar10 = param_3[0x11];
50: lVar17 = lVar21 + (long)((int)sVar10 * (int)sVar9) * 0x16a1;
51: sVar11 = param_3[10];
52: sVar12 = psVar14[10];
53: sVar13 = psVar14[0x12];
54: lVar18 = ((long)(int)((long)((int)sVar5 * (int)sVar7) * 0x2731 + lVar16 >> 0xb) + 0x10) * 0x2000;
55: lVar24 = (long)((int)param_3[2] * (int)psVar14[2]) * 0x2000 + 0x400;
56: lVar22 = lVar24 + (long)((int)sVar3 * (int)sVar13) * 0x16a1;
57: lVar19 = (long)(int)(lVar22 + (long)((int)sVar11 * (int)sVar12) * 0x2731 >> 0xb);
58: lVar25 = (long)(int)(lVar17 + (long)((int)sVar2 * (int)sVar6) * 0x2731 >> 0xb);
59: lVar20 = lVar19 * 0x16a1 + lVar18;
60: *puVar26 = *(undefined *)
61: (lVar15 + 0x80 + (ulong)((uint)(lVar25 * 0x2731 + lVar20 >> 0x12) & 0x3ff));
62: iStack56 = (int)(lVar24 + (long)((int)sVar3 * (int)sVar13) * -0x2d42 >> 0xb);
63: puVar26[2] = *(undefined *)
64: (lVar15 + 0x80 + (ulong)((uint)(lVar20 + lVar25 * -0x2731 >> 0x12) & 0x3ff));
65: iStack64 = (int)(lVar21 + (long)((int)sVar10 * (int)sVar9) * -0x2d42 >> 0xb);
66: puVar26[1] = *(undefined *)
67: (lVar15 + 0x80 + (ulong)((uint)(lVar18 + lVar19 * -0x2d42 >> 0x12) & 0x3ff));
68: puVar26 = (undefined *)(param_4[1] + uVar23);
69: lVar20 = ((long)(int)(lVar1 + (long)((int)sVar4 * (int)sVar8) * -0x2d42 >> 0xb) + 0x10) * 0x2000;
70: lVar1 = (long)iStack56 * 0x16a1 + lVar20;
71: *puVar26 = *(undefined *)
72: (lVar15 + 0x80 + (ulong)((uint)((long)iStack64 * 0x2731 + lVar1 >> 0x12) & 0x3ff));
73: puVar26[2] = *(undefined *)
74: (lVar15 + 0x80 + (ulong)((uint)(lVar1 + (long)iStack64 * -0x2731 >> 0x12) & 0x3ff));
75: puVar26[1] = *(undefined *)
76: (lVar15 + 0x80 + (ulong)((uint)(lVar20 + (long)iStack56 * -0x2d42 >> 0x12) & 0x3ff))
77: ;
78: puVar26 = (undefined *)(uVar23 + param_4[2]);
79: lVar16 = ((long)(int)(lVar16 + (long)((int)sVar5 * (int)sVar7) * -0x2731 >> 0xb) + 0x10) * 0x2000;
80: lVar22 = (long)(int)(lVar22 + (long)((int)sVar11 * (int)sVar12) * -0x2731 >> 0xb);
81: lVar1 = lVar16 + lVar22 * 0x16a1;
82: lVar17 = (long)(int)(lVar17 + (long)((int)sVar2 * (int)sVar6) * -0x2731 >> 0xb);
83: *puVar26 = *(undefined *)
84: (lVar15 + 0x80 + (ulong)((uint)(lVar1 + lVar17 * 0x2731 >> 0x12) & 0x3ff));
85: puVar26[2] = *(undefined *)
86: (lVar15 + 0x80 + (ulong)((uint)(lVar1 + lVar17 * -0x2731 >> 0x12) & 0x3ff));
87: puVar26[1] = *(undefined *)
88: (lVar15 + 0x80 + (ulong)((uint)(lVar16 + lVar22 * -0x2d42 >> 0x12) & 0x3ff));
89: return;
90: }
91: 
