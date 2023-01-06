1: 
2: void FUN_001417e0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: short *psVar1;
6: long lVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: long lVar13;
18: undefined *puVar14;
19: long lVar15;
20: short *psVar16;
21: int *piVar17;
22: long lVar18;
23: int *piVar19;
24: long lVar20;
25: long in_FS_OFFSET;
26: long *plStack424;
27: int aiStack360 [8];
28: int aiStack328 [8];
29: int aiStack296 [8];
30: int aiStack264 [8];
31: int aiStack232 [8];
32: int aiStack200 [8];
33: int aiStack168 [8];
34: int aiStack136 [8];
35: int aiStack104 [8];
36: int aiStack72 [2];
37: long lStack64;
38: 
39: psVar16 = *(short **)(param_2 + 0x58);
40: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
41: piVar19 = aiStack360;
42: lVar2 = *(long *)(param_1 + 0x1a8) + 0x80;
43: psVar1 = param_3 + 8;
44: piVar17 = piVar19;
45: do {
46: lVar5 = (long)((int)*param_3 * (int)*psVar16) * 0x2000 + 0x400;
47: lVar12 = (long)((int)param_3[0x10] * (int)psVar16[0x10]);
48: lVar8 = (long)((int)param_3[0x20] * (int)psVar16[0x20]);
49: lVar6 = lVar5 + (long)((int)param_3[0x30] * (int)psVar16[0x30]) * 0x16a1;
50: lVar5 = lVar5 + (long)((int)param_3[0x30] * (int)psVar16[0x30]) * -0x2d42;
51: lVar3 = lVar5 + (lVar12 - lVar8) * 0x16a1;
52: lVar4 = lVar6 + (lVar12 + lVar8) * -0x2a87 + lVar12 * 0x22ab;
53: lVar7 = lVar6 + lVar12 * -0x22ab + lVar8 * 0x7dc;
54: lVar9 = lVar6 + (lVar12 + lVar8) * 0x2a87 + lVar8 * -0x7dc;
55: lVar10 = (long)((int)param_3[8] * (int)psVar16[8]);
56: lVar6 = (long)((int)param_3[0x18] * (int)psVar16[0x18]) * -0x2731;
57: lVar15 = (long)((int)param_3[0x28] * (int)psVar16[0x28]);
58: lVar20 = (lVar10 + lVar15) * 0x1d17;
59: lVar13 = (long)((int)param_3[0x38] * (int)psVar16[0x38]);
60: lVar18 = (lVar10 + lVar13) * 0xf7a;
61: lVar11 = lVar6 + (lVar15 - lVar13) * -0x2c91 + lVar20;
62: lVar20 = lVar20 + lVar18 + (long)((int)param_3[0x18] * (int)psVar16[0x18]) * 0x2731;
63: lVar18 = lVar6 + (lVar15 - lVar13) * 0x2c91 + lVar18;
64: lVar13 = (lVar10 - lVar15) - lVar13;
65: param_3 = param_3 + 1;
66: psVar16 = psVar16 + 1;
67: piVar17[0x40] = (int)(lVar9 - lVar20 >> 0xb);
68: *piVar17 = (int)(lVar9 + lVar20 >> 0xb);
69: piVar17[0x38] = (int)(lVar3 + lVar13 * -0x2731 >> 0xb);
70: piVar17[0x10] = (int)(lVar4 + lVar11 >> 0xb);
71: piVar17[8] = (int)(lVar3 + lVar13 * 0x2731 >> 0xb);
72: piVar17[0x30] = (int)(lVar4 - lVar11 >> 0xb);
73: piVar17[0x28] = (int)(lVar7 - lVar18 >> 0xb);
74: piVar17[0x18] = (int)(lVar7 + lVar18 >> 0xb);
75: piVar17[0x20] = (int)(lVar5 + (lVar12 - lVar8) * -0x2d42 >> 0xb);
76: piVar17 = piVar17 + 1;
77: } while (param_3 != psVar1);
78: plStack424 = param_4;
79: do {
80: lVar11 = (long)piVar19[2];
81: lVar18 = (long)piVar19[4];
82: lVar15 = (long)piVar19[5];
83: puVar14 = (undefined *)((ulong)param_5 + *plStack424);
84: lVar12 = (long)piVar19[7];
85: lVar7 = ((long)*piVar19 + 0x10) * 0x2000;
86: lVar6 = lVar7 + (long)piVar19[6] * 0x16a1;
87: lVar7 = lVar7 + (long)piVar19[6] * -0x2d42;
88: lVar3 = lVar7 + (lVar11 - lVar18) * 0x16a1;
89: lVar4 = lVar6 + (lVar11 + lVar18) * -0x2a87 + lVar11 * 0x22ab;
90: lVar9 = lVar6 + lVar11 * -0x22ab + lVar18 * 0x7dc;
91: lVar8 = lVar6 + (lVar11 + lVar18) * 0x2a87 + lVar18 * -0x7dc;
92: lVar10 = (long)piVar19[1];
93: lVar6 = (long)piVar19[3] * -0x2731;
94: lVar13 = (lVar10 - lVar15) - lVar12;
95: lVar5 = (lVar10 + lVar12) * 0xf7a;
96: lVar10 = (lVar10 + lVar15) * 0x1d17;
97: lVar20 = lVar6 + (lVar15 - lVar12) * -0x2c91 + lVar10;
98: lVar10 = lVar10 + lVar5 + (long)piVar19[3] * 0x2731;
99: lVar5 = lVar6 + (lVar15 - lVar12) * 0x2c91 + lVar5;
100: piVar19 = piVar19 + 8;
101: *puVar14 = *(undefined *)(lVar2 + (ulong)((uint)(lVar8 + lVar10 >> 0x12) & 0x3ff));
102: puVar14[8] = *(undefined *)(lVar2 + (ulong)((uint)(lVar8 - lVar10 >> 0x12) & 0x3ff));
103: puVar14[1] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 + lVar13 * 0x2731 >> 0x12) & 0x3ff));
104: puVar14[7] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 + lVar13 * -0x2731 >> 0x12) & 0x3ff));
105: puVar14[2] = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 + lVar20 >> 0x12) & 0x3ff));
106: puVar14[6] = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 - lVar20 >> 0x12) & 0x3ff));
107: puVar14[3] = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 + lVar5 >> 0x12) & 0x3ff));
108: puVar14[5] = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 - lVar5 >> 0x12) & 0x3ff));
109: plStack424 = plStack424 + 1;
110: puVar14[4] = *(undefined *)
111: (lVar2 + (ulong)((uint)(lVar7 + (lVar11 - lVar18) * -0x2d42 >> 0x12) & 0x3ff));
112: } while (piVar19 != aiStack72);
113: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
114: return;
115: }
116: /* WARNING: Subroutine does not return */
117: __stack_chk_fail();
118: }
119: 
