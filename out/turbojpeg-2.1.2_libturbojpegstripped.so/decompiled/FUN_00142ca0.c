1: 
2: void FUN_00142ca0(long param_1,long param_2,short *param_3,long *param_4,uint param_5)
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
15: undefined *puVar11;
16: int *piVar12;
17: long lVar13;
18: long lVar14;
19: long lVar15;
20: long lVar16;
21: long lVar17;
22: long lVar18;
23: long lVar19;
24: int *piVar20;
25: long lVar21;
26: short *psVar22;
27: long lVar23;
28: long lVar24;
29: long lVar25;
30: long lVar26;
31: long lVar27;
32: long in_FS_OFFSET;
33: long *plStack592;
34: int aiStack488 [8];
35: int aiStack456 [8];
36: int aiStack424 [8];
37: int aiStack392 [8];
38: int aiStack360 [8];
39: int aiStack328 [8];
40: int aiStack296 [8];
41: int aiStack264 [8];
42: int aiStack232 [8];
43: int aiStack200 [8];
44: int aiStack168 [8];
45: int aiStack136 [8];
46: int aiStack104 [8];
47: int aiStack72 [2];
48: long lStack64;
49: 
50: psVar22 = *(short **)(param_2 + 0x58);
51: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
52: piVar20 = aiStack488;
53: lVar2 = *(long *)(param_1 + 0x1a8) + 0x80;
54: psVar1 = param_3 + 8;
55: piVar12 = piVar20;
56: do {
57: lVar5 = (long)((int)*param_3 * (int)*psVar22) * 0x2000 + 0x400;
58: lVar6 = (long)((int)param_3[0x10] * (int)psVar22[0x10]);
59: lVar4 = (long)((int)param_3[0x20] * (int)psVar22[0x20]) +
60: (long)((int)param_3[0x30] * (int)psVar22[0x30]);
61: lVar14 = (long)((int)param_3[0x20] * (int)psVar22[0x20]) -
62: (long)((int)param_3[0x30] * (int)psVar22[0x30]);
63: lVar8 = lVar14 * 0x319 + lVar5;
64: lVar3 = lVar6 * 0x2bf1 + lVar4 * 0x24f9 + lVar8;
65: lVar7 = lVar6 * 0x100c + lVar4 * -0x24f9 + lVar8;
66: lVar8 = lVar8 + lVar14 * 0xc7c;
67: lVar17 = lVar6 * 0x21e0 + lVar4 * -0xa20 + lVar8;
68: lVar8 = lVar8 + lVar4 * 0xa20 + lVar6 * -0x2812;
69: lVar9 = lVar14 * 0x1dfe - lVar5;
70: lVar15 = (lVar6 * -0x574 + lVar4 * -0xdf2) - lVar9;
71: lVar9 = (lVar4 * 0xdf2 + lVar6 * -0x19b5) - lVar9;
72: lVar10 = (long)((int)param_3[8] * (int)psVar22[8]);
73: lVar18 = (long)((int)param_3[0x18] * (int)psVar22[0x18]);
74: lVar4 = (long)((int)param_3[0x28] * (int)psVar22[0x28]);
75: lVar24 = (lVar10 + lVar18) * 0x2a50;
76: lVar16 = (long)((int)param_3[0x38] * (int)psVar22[0x38]);
77: lVar21 = (lVar10 + lVar4) * 0x253e;
78: lVar26 = (lVar10 + lVar16) * 0x1e02;
79: lVar13 = lVar24 + lVar21 + lVar26 + lVar10 * -0x40a5;
80: lVar19 = (lVar18 + lVar4) * -0xad5;
81: lVar23 = (lVar10 + lVar16) * 0xad5;
82: lVar25 = (lVar18 + lVar16) * -0x253e;
83: lVar24 = lVar18 * 0x1acb + lVar19 + lVar24 + lVar25;
84: lVar27 = (lVar4 + lVar16) * -0x1508;
85: lVar21 = lVar19 + lVar4 * -0x324f + lVar21 + lVar27;
86: lVar27 = lVar27 + lVar16 * 0x4694 + lVar25 + lVar26;
87: lVar19 = (lVar4 - lVar18) * 0x1e02;
88: lVar10 = lVar10 * 0xa33 + lVar23 + lVar18 * -0xeea + lVar19;
89: param_3 = param_3 + 1;
90: psVar22 = psVar22 + 1;
91: lVar23 = lVar23 + lVar4 * 0xc4e + lVar19 + lVar16 * -0x37c1;
92: *piVar12 = (int)(lVar3 + lVar13 >> 0xb);
93: piVar12[0x60] = (int)(lVar3 - lVar13 >> 0xb);
94: piVar12[8] = (int)(lVar17 + lVar24 >> 0xb);
95: piVar12[0x58] = (int)(lVar17 - lVar24 >> 0xb);
96: piVar12[0x10] = (int)(lVar7 + lVar21 >> 0xb);
97: piVar12[0x50] = (int)(lVar7 - lVar21 >> 0xb);
98: piVar12[0x18] = (int)(lVar15 + lVar27 >> 0xb);
99: piVar12[0x48] = (int)(lVar15 - lVar27 >> 0xb);
100: piVar12[0x20] = (int)(lVar9 + lVar10 >> 0xb);
101: piVar12[0x40] = (int)(lVar9 - lVar10 >> 0xb);
102: piVar12[0x28] = (int)(lVar8 + lVar23 >> 0xb);
103: piVar12[0x38] = (int)(lVar8 - lVar23 >> 0xb);
104: piVar12[0x30] = (int)((lVar14 - lVar6) * 0x2d41 + lVar5 >> 0xb);
105: piVar12 = piVar12 + 1;
106: } while (param_3 != psVar1);
107: plStack592 = param_4;
108: do {
109: lVar19 = (long)piVar20[2];
110: puVar11 = (undefined *)((ulong)param_5 + *plStack592);
111: lVar5 = (long)piVar20[4] + (long)piVar20[6];
112: lVar14 = (long)piVar20[4] - (long)piVar20[6];
113: lVar21 = ((long)*piVar20 + 0x10) * 0x2000;
114: lVar9 = lVar14 * 0x319 + lVar21;
115: lVar4 = lVar19 * 0x2bf1 + lVar5 * 0x24f9 + lVar9;
116: lVar10 = (long)piVar20[3];
117: lVar3 = lVar19 * 0x100c + lVar5 * -0x24f9 + lVar9;
118: lVar9 = lVar9 + lVar14 * 0xc7c;
119: lVar17 = lVar19 * 0x21e0 + lVar5 * -0xa20 + lVar9;
120: lVar9 = lVar9 + lVar5 * 0xa20 + lVar19 * -0x2812;
121: lVar7 = lVar14 * 0x1dfe + ((long)*piVar20 + 0x10) * -0x2000;
122: lVar24 = (long)piVar20[7];
123: lVar15 = (lVar19 * -0x574 + lVar5 * -0xdf2) - lVar7;
124: lVar7 = (lVar5 * 0xdf2 + lVar19 * -0x19b5) - lVar7;
125: lVar6 = (long)piVar20[1];
126: lVar5 = (long)piVar20[5];
127: lVar18 = (lVar6 + lVar10) * 0x2a50;
128: lVar16 = (lVar6 + lVar5) * 0x253e;
129: lVar26 = (lVar6 + lVar24) * 0x1e02;
130: lVar23 = (lVar6 + lVar24) * 0xad5;
131: lVar8 = lVar18 + lVar16 + lVar26 + lVar6 * -0x40a5;
132: lVar13 = (lVar10 + lVar5) * -0xad5;
133: lVar25 = (lVar10 + lVar24) * -0x253e;
134: lVar18 = lVar10 * 0x1acb + lVar13 + lVar18 + lVar25;
135: lVar27 = (lVar5 + lVar24) * -0x1508;
136: lVar16 = lVar13 + lVar5 * -0x324f + lVar16 + lVar27;
137: lVar27 = lVar27 + lVar24 * 0x4694 + lVar25 + lVar26;
138: lVar13 = (lVar5 - lVar10) * 0x1e02;
139: lVar6 = lVar6 * 0xa33 + lVar23 + lVar10 * -0xeea + lVar13;
140: lVar23 = lVar23 + lVar5 * 0xc4e + lVar13 + lVar24 * -0x37c1;
141: *puVar11 = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 + lVar8 >> 0x12) & 0x3ff));
142: puVar11[0xc] = *(undefined *)(lVar2 + (ulong)((uint)(lVar4 - lVar8 >> 0x12) & 0x3ff));
143: puVar11[1] = *(undefined *)(lVar2 + (ulong)((uint)(lVar17 + lVar18 >> 0x12) & 0x3ff));
144: puVar11[0xb] = *(undefined *)(lVar2 + (ulong)((uint)(lVar17 - lVar18 >> 0x12) & 0x3ff));
145: puVar11[2] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 + lVar16 >> 0x12) & 0x3ff));
146: puVar11[10] = *(undefined *)(lVar2 + (ulong)((uint)(lVar3 - lVar16 >> 0x12) & 0x3ff));
147: puVar11[3] = *(undefined *)(lVar2 + (ulong)((uint)(lVar15 + lVar27 >> 0x12) & 0x3ff));
148: puVar11[9] = *(undefined *)(lVar2 + (ulong)((uint)(lVar15 - lVar27 >> 0x12) & 0x3ff));
149: puVar11[4] = *(undefined *)(lVar2 + (ulong)((uint)(lVar7 + lVar6 >> 0x12) & 0x3ff));
150: puVar11[8] = *(undefined *)(lVar2 + (ulong)((uint)(lVar7 - lVar6 >> 0x12) & 0x3ff));
151: puVar11[5] = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 + lVar23 >> 0x12) & 0x3ff));
152: puVar11[7] = *(undefined *)(lVar2 + (ulong)((uint)(lVar9 - lVar23 >> 0x12) & 0x3ff));
153: piVar20 = piVar20 + 8;
154: plStack592 = plStack592 + 1;
155: puVar11[6] = *(undefined *)
156: (lVar2 + (ulong)((uint)((lVar14 - lVar19) * 0x2d41 + lVar21 >> 0x12) & 0x3ff));
157: } while (piVar20 != aiStack72);
158: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
159: return;
160: }
161: /* WARNING: Subroutine does not return */
162: __stack_chk_fail();
163: }
164: 