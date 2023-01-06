1: 
2: void FUN_001404f0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: long lVar2;
7: long lVar3;
8: int *piVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: undefined *puVar16;
21: short *psVar17;
22: long lVar18;
23: long lVar19;
24: int *piVar20;
25: long in_FS_OFFSET;
26: int aiStack264 [7];
27: int aiStack236 [7];
28: int aiStack208 [7];
29: int aiStack180 [7];
30: int aiStack152 [7];
31: int aiStack124 [7];
32: int aiStack96 [7];
33: int iStack68;
34: long lStack64;
35: 
36: psVar17 = *(short **)(param_2 + 0x58);
37: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
38: piVar4 = aiStack264;
39: psVar1 = param_3 + 7;
40: lVar18 = *(long *)(param_1 + 0x1a8) + 0x80;
41: piVar20 = piVar4;
42: do {
43: lVar14 = (long)((int)*param_3 * (int)*psVar17) * 0x2000 + 0x400;
44: lVar8 = (long)((int)param_3[0x30] * (int)psVar17[0x30]);
45: lVar6 = (long)((int)param_3[0x10] * (int)psVar17[0x10]);
46: lVar5 = (long)((int)param_3[0x20] * (int)psVar17[0x20]);
47: lVar3 = (lVar5 - lVar8) * 0x1c37;
48: lVar11 = (lVar6 - lVar5) * 0xa12;
49: lVar15 = lVar3 + lVar11 + lVar14 + lVar5 * -0x3aeb;
50: lVar2 = (lVar6 + lVar8) * 0x28c6 + lVar14;
51: lVar3 = lVar8 * -0x27d + lVar2 + lVar3;
52: lVar11 = lVar6 * -0x4f0f + lVar2 + lVar11;
53: lVar12 = (long)((int)param_3[8] * (int)psVar17[8]);
54: lVar9 = (long)((int)param_3[0x18] * (int)psVar17[0x18]);
55: lVar7 = (long)((int)param_3[0x28] * (int)psVar17[0x28]);
56: lVar19 = (lVar12 + lVar9) * 0x1def;
57: lVar10 = (lVar9 + lVar7) * -0x2c1f;
58: lVar2 = (lVar12 - lVar9) * 0x573 + lVar19 + lVar10;
59: lVar13 = (lVar12 + lVar7) * 0x13a3;
60: param_3 = param_3 + 1;
61: psVar17 = psVar17 + 1;
62: lVar9 = lVar19 + (lVar12 - lVar9) * -0x573 + lVar13;
63: lVar10 = lVar10 + lVar7 * 0x3bde + lVar13;
64: piVar20[0x2a] = (int)(lVar3 - lVar9 >> 0xb);
65: *piVar20 = (int)(lVar3 + lVar9 >> 0xb);
66: piVar20[0x23] = (int)(lVar15 - lVar2 >> 0xb);
67: piVar20[7] = (int)(lVar15 + lVar2 >> 0xb);
68: piVar20[0x15] = (int)(lVar14 + (lVar5 - (lVar6 + lVar8)) * 0x2d41 >> 0xb);
69: piVar20[0x1c] = (int)(lVar11 - lVar10 >> 0xb);
70: piVar20[0xe] = (int)(lVar11 + lVar10 >> 0xb);
71: piVar20 = piVar20 + 1;
72: } while (param_3 != psVar1);
73: do {
74: lVar7 = (long)piVar4[2];
75: lVar3 = (long)piVar4[4];
76: lVar13 = (long)piVar4[6];
77: puVar16 = (undefined *)((ulong)param_5 + *param_4);
78: lVar9 = (lVar3 - lVar13) * 0x1c37;
79: lVar5 = ((long)*piVar4 + 0x10) * 0x2000;
80: lVar11 = (lVar7 - lVar3) * 0xa12;
81: lVar6 = lVar9 + lVar11 + lVar5 + lVar3 * -0x3aeb;
82: lVar14 = (long)piVar4[1];
83: lVar2 = (lVar7 + lVar13) * 0x28c6 + lVar5;
84: lVar8 = (long)piVar4[5];
85: lVar9 = lVar13 * -0x27d + lVar2 + lVar9;
86: lVar10 = (long)piVar4[3];
87: lVar11 = lVar7 * -0x4f0f + lVar2 + lVar11;
88: lVar2 = (lVar14 + lVar10) * 0x1def;
89: lVar15 = (lVar14 + lVar8) * 0x13a3;
90: lVar12 = (lVar10 + lVar8) * -0x2c1f;
91: lVar19 = lVar2 + (lVar14 - lVar10) * -0x573 + lVar15;
92: lVar2 = (lVar14 - lVar10) * 0x573 + lVar2 + lVar12;
93: lVar12 = lVar12 + lVar8 * 0x3bde + lVar15;
94: piVar4 = piVar4 + 7;
95: param_4 = param_4 + 1;
96: *puVar16 = *(undefined *)(lVar18 + (ulong)((uint)(lVar9 + lVar19 >> 0x12) & 0x3ff));
97: puVar16[6] = *(undefined *)(lVar18 + (ulong)((uint)(lVar9 - lVar19 >> 0x12) & 0x3ff));
98: puVar16[1] = *(undefined *)(lVar18 + (ulong)((uint)(lVar6 + lVar2 >> 0x12) & 0x3ff));
99: puVar16[5] = *(undefined *)(lVar18 + (ulong)((uint)(lVar6 - lVar2 >> 0x12) & 0x3ff));
100: puVar16[2] = *(undefined *)(lVar18 + (ulong)((uint)(lVar11 + lVar12 >> 0x12) & 0x3ff));
101: puVar16[4] = *(undefined *)(lVar18 + (ulong)((uint)(lVar11 - lVar12 >> 0x12) & 0x3ff));
102: puVar16[3] = *(undefined *)
103: (lVar18 + (ulong)((uint)(lVar5 + (lVar3 - (lVar7 + lVar13)) * 0x2d41 >> 0x12) &
104: 0x3ff));
105: } while (piVar4 != &iStack68);
106: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
107: return;
108: }
109: /* WARNING: Subroutine does not return */
110: __stack_chk_fail();
111: }
112: 
