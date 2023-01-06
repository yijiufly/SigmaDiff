1: 
2: void FUN_0013fad0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: short sVar2;
7: short sVar3;
8: short sVar4;
9: short sVar5;
10: int iVar6;
11: undefined *puVar7;
12: long lVar8;
13: short sVar9;
14: short sVar10;
15: short sVar11;
16: short sVar12;
17: short sVar13;
18: int *piVar14;
19: int *piVar15;
20: short *psVar16;
21: short sVar17;
22: int iVar18;
23: short sVar19;
24: int iVar20;
25: long in_FS_OFFSET;
26: int aiStack328 [8];
27: int aiStack296 [8];
28: int aiStack264 [8];
29: int aiStack232 [8];
30: int aiStack200 [8];
31: int aiStack168 [8];
32: int aiStack136 [8];
33: int aiStack104 [8];
34: int aiStack72 [2];
35: long lStack64;
36: 
37: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
38: lVar8 = *(long *)(param_1 + 0x1a8) + 0x80;
39: piVar14 = aiStack328;
40: psVar16 = *(short **)(param_2 + 0x58);
41: do {
42: piVar15 = piVar14 + 1;
43: if ((((param_3[8] == 0) && (param_3[0x10] == 0)) && (param_3[0x18] == 0)) &&
44: (((param_3[0x20] == 0 && (param_3[0x28] == 0)) &&
45: ((param_3[0x30] == 0 && (param_3[0x38] == 0)))))) {
46: iVar6 = (int)*psVar16 * (int)*param_3;
47: *piVar14 = iVar6;
48: piVar14[8] = iVar6;
49: piVar14[0x10] = iVar6;
50: piVar14[0x18] = iVar6;
51: piVar14[0x20] = iVar6;
52: piVar14[0x28] = iVar6;
53: piVar14[0x30] = iVar6;
54: piVar14[0x38] = iVar6;
55: }
56: else {
57: sVar19 = param_3[0x20] * psVar16[0x20];
58: sVar9 = param_3[0x10] * psVar16[0x10];
59: sVar17 = param_3[0x30] * psVar16[0x30];
60: sVar10 = param_3[0x18] * psVar16[0x18];
61: sVar13 = param_3[0x38] * psVar16[0x38];
62: sVar4 = param_3[8] * psVar16[8];
63: sVar2 = param_3[0x28] * psVar16[0x28];
64: sVar12 = *param_3 * *psVar16;
65: sVar3 = sVar10 + sVar2;
66: sVar2 = sVar2 - sVar10;
67: sVar11 = sVar4 + sVar13;
68: sVar10 = sVar12 + sVar19;
69: sVar12 = sVar12 - sVar19;
70: sVar19 = sVar9 + sVar17;
71: sVar4 = sVar4 - sVar13;
72: sVar13 = sVar3 + sVar11;
73: iVar20 = (int)(short)(sVar10 + sVar19);
74: iVar6 = (int)(short)(sVar10 - sVar19);
75: sVar19 = (short)((ulong)((long)((int)sVar9 - (int)sVar17) * 0x16a) >> 8) - sVar19;
76: sVar9 = (short)((ulong)((long)((int)sVar2 + (int)sVar4) * 0x1d9) >> 8);
77: sVar10 = ((short)((ulong)((long)sVar2 * -0x29d) >> 8) - sVar13) + sVar9;
78: piVar14[0x38] = iVar20 - sVar13;
79: *piVar14 = iVar20 + sVar13;
80: iVar18 = (int)(short)(sVar12 + sVar19);
81: iVar20 = (int)(short)(sVar12 - sVar19);
82: sVar13 = (short)((ulong)((long)((int)sVar11 - (int)sVar3) * 0x16a) >> 8) - sVar10;
83: piVar14[8] = iVar18 + sVar10;
84: piVar14[0x30] = iVar18 - sVar10;
85: piVar14[0x10] = iVar20 + sVar13;
86: piVar14[0x28] = iVar20 - sVar13;
87: iVar20 = (int)(short)(sVar13 + ((short)((ulong)((long)sVar4 * 0x115) >> 8) - sVar9));
88: piVar14[0x18] = iVar6 - iVar20;
89: piVar14[0x20] = iVar6 + iVar20;
90: }
91: param_3 = param_3 + 1;
92: piVar14 = piVar15;
93: psVar16 = psVar16 + 1;
94: } while (piVar15 != aiStack296);
95: piVar14 = aiStack328;
96: do {
97: piVar15 = piVar14 + 8;
98: puVar7 = (undefined *)((ulong)param_5 + *param_4);
99: if ((((piVar14[1] == 0) && (piVar14[2] == 0)) &&
100: ((piVar14[3] == 0 && (((piVar14[4] == 0 && (piVar14[5] == 0)) && (piVar14[6] == 0)))))) &&
101: (piVar14[7] == 0)) {
102: uVar1 = *(undefined *)(lVar8 + (ulong)(*piVar14 >> 5 & 0x3ff));
103: *puVar7 = uVar1;
104: puVar7[1] = uVar1;
105: puVar7[2] = uVar1;
106: puVar7[3] = uVar1;
107: puVar7[4] = uVar1;
108: puVar7[5] = uVar1;
109: puVar7[6] = uVar1;
110: puVar7[7] = uVar1;
111: }
112: else {
113: sVar10 = (short)piVar14[3];
114: sVar3 = (short)piVar14[5];
115: sVar12 = sVar10 + sVar3;
116: sVar3 = sVar3 - sVar10;
117: sVar10 = (short)piVar14[7];
118: sVar5 = (short)piVar14[1];
119: sVar17 = sVar10 + sVar5;
120: sVar5 = sVar5 - sVar10;
121: sVar13 = (short)piVar14[4];
122: sVar19 = (short)*piVar14;
123: sVar10 = sVar13 + sVar19;
124: sVar19 = sVar19 - sVar13;
125: sVar9 = (short)piVar14[2];
126: sVar2 = (short)piVar14[6];
127: sVar13 = sVar9 + sVar2;
128: sVar11 = sVar12 + sVar17;
129: iVar6 = (int)(short)(sVar10 + sVar13);
130: sVar9 = (short)((ulong)((long)((int)sVar9 - (int)sVar2) * 0x16a) >> 8) - sVar13;
131: *puVar7 = *(undefined *)(lVar8 + (ulong)(iVar6 + sVar11 >> 5 & 0x3ff));
132: sVar4 = (short)((ulong)((long)((int)sVar3 + (int)sVar5) * 0x1d9) >> 8);
133: sVar2 = ((short)((ulong)((long)sVar3 * -0x29d) >> 8) - sVar11) + sVar4;
134: sVar12 = (short)((ulong)((long)((int)sVar17 - (int)sVar12) * 0x16a) >> 8) - sVar2;
135: puVar7[7] = *(undefined *)(lVar8 + (ulong)(iVar6 - sVar11 >> 5 & 0x3ff));
136: iVar6 = (int)(short)(sVar19 - sVar9);
137: iVar20 = (int)(short)(sVar19 + sVar9);
138: puVar7[1] = *(undefined *)(lVar8 + (ulong)(iVar20 + sVar2 >> 5 & 0x3ff));
139: puVar7[6] = *(undefined *)(lVar8 + (ulong)(iVar20 - sVar2 >> 5 & 0x3ff));
140: iVar18 = (int)(short)(sVar10 - sVar13);
141: puVar7[2] = *(undefined *)(lVar8 + (ulong)(iVar6 + sVar12 >> 5 & 0x3ff));
142: iVar20 = (int)(short)(sVar12 + ((short)((ulong)((long)sVar5 * 0x115) >> 8) - sVar4));
143: puVar7[5] = *(undefined *)(lVar8 + (ulong)(iVar6 - sVar12 >> 5 & 0x3ff));
144: puVar7[4] = *(undefined *)(lVar8 + (ulong)(iVar18 + iVar20 >> 5 & 0x3ff));
145: puVar7[3] = *(undefined *)(lVar8 + (ulong)(iVar18 - iVar20 >> 5 & 0x3ff));
146: }
147: param_4 = param_4 + 1;
148: piVar14 = piVar15;
149: } while (piVar15 != aiStack72);
150: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
151: /* WARNING: Subroutine does not return */
152: __stack_chk_fail();
153: }
154: return;
155: }
156: 
