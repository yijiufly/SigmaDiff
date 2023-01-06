1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00168820(undefined8 param_1,long param_2,short *param_3,long *param_4,uint param_5)
5: 
6: {
7: long lVar1;
8: short *psVar2;
9: int iVar3;
10: uint6 uVar4;
11: int iVar9;
12: int iVar10;
13: undefined auVar8 [16];
14: int iVar11;
15: int iVar12;
16: uint6 uVar13;
17: int iVar15;
18: int iVar16;
19: undefined auVar14 [16];
20: int iVar17;
21: uint6 uVar18;
22: undefined auVar22 [16];
23: uint6 uVar23;
24: int iVar24;
25: undefined auVar25 [16];
26: undefined auVar26 [16];
27: undefined2 uVar27;
28: int iVar28;
29: undefined8 uVar5;
30: unkbyte10 Var6;
31: undefined auVar7 [12];
32: undefined8 uVar19;
33: unkbyte10 Var20;
34: undefined auVar21 [12];
35: 
36: psVar2 = *(short **)(param_2 + 0x58);
37: uVar4 = CONCAT24(param_3[10] * psVar2[10],CONCAT22(param_3[9] * psVar2[9],param_3[8] * psVar2[8]))
38: ;
39: uVar5 = CONCAT26(param_3[0xb] * psVar2[0xb],uVar4);
40: Var6 = CONCAT28(param_3[0xc] * psVar2[0xc],uVar5);
41: auVar7 = CONCAT210(param_3[0xd] * psVar2[0xd],Var6);
42: uVar13 = CONCAT24(param_3[0x1a] * psVar2[0x1a],
43: CONCAT22(param_3[0x19] * psVar2[0x19],param_3[0x18] * psVar2[0x18]));
44: uVar18 = CONCAT24(param_3[0x2a] * psVar2[0x2a],
45: CONCAT22(param_3[0x29] * psVar2[0x29],param_3[0x28] * psVar2[0x28]));
46: uVar19 = CONCAT26(param_3[0x2b] * psVar2[0x2b],uVar18);
47: Var20 = CONCAT28(param_3[0x2c] * psVar2[0x2c],uVar19);
48: auVar21 = CONCAT210(param_3[0x2d] * psVar2[0x2d],Var20);
49: uVar23 = CONCAT24(param_3[0x3a] * psVar2[0x3a],
50: CONCAT22(param_3[0x39] * psVar2[0x39],param_3[0x38] * psVar2[0x38]));
51: auVar14 = CONCAT412(0xffff0000,CONCAT48(0xffff0000,0xffff0000ffff0000));
52: auVar25 = pmaddwd(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
53: SUB164(CONCAT214(param_3[0x1b] * psVar2[0x1b],
54: CONCAT212(param_3[0xb] *
55: psVar2[0xb],auVar7)) >>
56: 0x60,0),
57: CONCAT210(param_3[0x1a] * psVar2[0x1a],Var6)) >>
58: 0x50,0),CONCAT28(param_3[10] * psVar2[10],uVar5))
59: >> 0x40,0),
60: (((ulong)uVar13 & 0xffff0000) >> 0x10) << 0x30) >>
61: 0x30,0),(uVar4 >> 0x10) << 0x20) >> 0x20,0),
62: CONCAT22(param_3[0x18] * psVar2[0x18],param_3[8] * psVar2[8])),
63: _DAT_0019ccf0);
64: auVar26 = pmaddwd(CONCAT124(SUB1612(CONCAT106(SUB1610(CONCAT88(SUB168(CONCAT610(SUB166(CONCAT412(
65: SUB164(CONCAT214(param_3[0x3b] * psVar2[0x3b],
66: CONCAT212(param_3[0x2b] *
67: psVar2[0x2b],auVar21))
68: >> 0x60,0),
69: CONCAT210(param_3[0x3a] * psVar2[0x3a],Var20)) >>
70: 0x50,0),CONCAT28(param_3[0x2a] * psVar2[0x2a],
71: uVar19)) >> 0x40,0),
72: (((ulong)uVar23 & 0xffff0000) >> 0x10) << 0x30) >>
73: 0x30,0),(uVar18 >> 0x10) << 0x20) >> 0x20,0),
74: CONCAT22(param_3[0x38] * psVar2[0x38],param_3[0x28] * psVar2[0x28])),
75: _DAT_0019cd00);
76: auVar8 = pmaddwd(CONCAT412(SUB164(CONCAT214(param_3[0xf] * psVar2[0xf],
77: CONCAT212(param_3[0xe] * psVar2[0xe],auVar7)) >> 0x70,
78: 0),
79: CONCAT48(SUB124(auVar7 >> 0x50,0),
80: CONCAT44((uint)((ulong)uVar5 >> 0x30),
81: (uint)(ushort)(param_3[9] * psVar2[9])))) |
82: CONCAT214(param_3[0x1f] * psVar2[0x1f],
83: CONCAT212(param_3[0x1e] * psVar2[0x1e],
84: CONCAT210(param_3[0x1d] * psVar2[0x1d],
85: CONCAT28(param_3[0x1c] * psVar2[0x1c],
86: CONCAT26(param_3[0x1b] * psVar2[0x1b],
87: uVar13))))) & auVar14,
88: _DAT_0019ccf0);
89: auVar22 = pmaddwd(CONCAT412(SUB164(CONCAT214(param_3[0x2f] * psVar2[0x2f],
90: CONCAT212(param_3[0x2e] * psVar2[0x2e],auVar21)) >>
91: 0x70,0),
92: CONCAT48(SUB124(auVar21 >> 0x50,0),
93: CONCAT44((uint)((ulong)uVar19 >> 0x30),
94: (uint)(ushort)(param_3[0x29] * psVar2[0x29])))) |
95: CONCAT214(param_3[0x3f] * psVar2[0x3f],
96: CONCAT212(param_3[0x3e] * psVar2[0x3e],
97: CONCAT210(param_3[0x3d] * psVar2[0x3d],
98: CONCAT28(param_3[0x3c] * psVar2[0x3c],
99: CONCAT26(param_3[0x3b] * psVar2[0x3b],
100: uVar23))))) & auVar14,
101: _DAT_0019cd00);
102: iVar24 = SUB164(auVar25,0) + SUB164(auVar26,0);
103: iVar3 = SUB164(auVar8,0) + SUB164(auVar22,0);
104: iVar9 = SUB164(auVar8 >> 0x20,0) + SUB164(auVar22 >> 0x20,0);
105: iVar10 = SUB164(auVar8 >> 0x40,0) + SUB164(auVar22 >> 0x40,0);
106: iVar11 = SUB164(auVar8 >> 0x60,0) + SUB164(auVar22 >> 0x60,0);
107: iVar12 = CONCAT22(param_3[1] * psVar2[1],*param_3 * *psVar2);
108: auVar14 = CONCAT214(param_3[7] * psVar2[7],
109: CONCAT212(param_3[6] * psVar2[6],
110: CONCAT210(param_3[5] * psVar2[5],
111: CONCAT28(param_3[4] * psVar2[4],
112: CONCAT26(param_3[3] * psVar2[3],
113: CONCAT24(param_3[2] * psVar2[2],iVar12))
114: )))) & auVar14;
115: iVar28 = (iVar12 << 0x10) >> 1;
116: iVar12 = SUB164(auVar14,0) >> 1;
117: iVar15 = SUB164(auVar14 >> 0x20,0) >> 1;
118: iVar16 = SUB164(auVar14 >> 0x40,0) >> 1;
119: iVar17 = SUB164(auVar14 >> 0x61,0);
120: auVar8 = CONCAT412((iVar15 - iVar9) + 0x1000 >> 0xd,
121: CONCAT48((iVar12 - iVar3) + 0x1000 >> 0xd,
122: CONCAT44(iVar15 + iVar9 + 0x1000 >> 0xd,iVar12 + iVar3 + 0x1000 >> 0xd
123: )));
124: auVar14 = CONCAT412((iVar17 - iVar11) + 0x1000 >> 0xd,
125: CONCAT48((iVar16 - iVar10) + 0x1000 >> 0xd,
126: CONCAT44(iVar17 + iVar11 + 0x1000 >> 0xd,
127: iVar16 + iVar10 + 0x1000 >> 0xd)));
128: auVar8 = packssdw(auVar8,auVar8);
129: auVar14 = packssdw(auVar14,auVar14);
130: auVar8 = pmaddwd(auVar8,_DAT_0019ccf0);
131: auVar14 = pmaddwd(auVar14,_DAT_0019cd00);
132: iVar3 = SUB164(auVar8,0) + SUB164(auVar14,0);
133: iVar9 = SUB164(auVar8 >> 0x20,0) + SUB164(auVar14 >> 0x20,0);
134: iVar10 = (iVar28 + iVar24 + 0x1000 >> 0xd) * 0x8000;
135: iVar11 = ((iVar28 - iVar24) + 0x1000 >> 0xd) * 0x8000;
136: auVar8 = CONCAT412((iVar11 - iVar9) + 0x80000 >> 0x14,
137: CONCAT48(iVar11 + iVar9 + 0x80000 >> 0x14,
138: CONCAT44((iVar10 - iVar3) + 0x80000 >> 0x14,
139: iVar10 + iVar3 + 0x80000 >> 0x14)));
140: auVar8 = packssdw(auVar8,auVar8);
141: auVar8 = packsswb(auVar8,auVar8);
142: uVar27 = CONCAT11(SUB161(auVar8 >> 8,0) + -0x80,SUB161(auVar8,0) + -0x80);
143: lVar1 = param_4[1];
144: *(undefined2 *)(*param_4 + (ulong)param_5) = uVar27;
145: *(short *)(lVar1 + (ulong)param_5) =
146: (short)(CONCAT13(SUB161(auVar8 >> 0x18,0) + -0x80,
147: CONCAT12(SUB161(auVar8 >> 0x10,0) + -0x80,uVar27)) >> 0x10);
148: return;
149: }
150: 
