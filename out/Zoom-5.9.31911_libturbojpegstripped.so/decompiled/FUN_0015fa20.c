1: 
2: void FUN_0015fa20(long *param_1,ulong param_2,undefined (*param_3) [16])
3: 
4: {
5: float fVar1;
6: float fVar2;
7: float fVar3;
8: float fVar4;
9: float fVar5;
10: float fVar6;
11: long lVar7;
12: byte bVar8;
13: ushort uVar9;
14: short sVar26;
15: char cVar27;
16: char cVar29;
17: short sVar28;
18: char cVar30;
19: char cVar32;
20: short sVar31;
21: short sVar33;
22: byte bVar34;
23: ushort uVar35;
24: short sVar52;
25: char cVar53;
26: char cVar55;
27: short sVar54;
28: char cVar56;
29: char cVar58;
30: short sVar57;
31: short sVar59;
32: char cVar61;
33: char cVar62;
34: char cVar63;
35: char cVar64;
36: char cVar65;
37: char cVar66;
38: char cVar67;
39: char cVar68;
40: char cVar69;
41: undefined auVar60 [16];
42: uint3 uVar10;
43: uint uVar11;
44: uint5 uVar12;
45: uint6 uVar13;
46: uint7 uVar14;
47: ulong uVar15;
48: unkbyte9 Var16;
49: unkbyte10 Var17;
50: undefined auVar18 [11];
51: undefined auVar19 [12];
52: undefined auVar20 [13];
53: undefined auVar21 [16];
54: undefined auVar22 [16];
55: undefined auVar23 [16];
56: undefined auVar24 [16];
57: undefined auVar25 [16];
58: uint3 uVar36;
59: uint uVar37;
60: uint5 uVar38;
61: uint6 uVar39;
62: uint7 uVar40;
63: ulong uVar41;
64: unkbyte9 Var42;
65: unkbyte10 Var43;
66: undefined auVar44 [11];
67: undefined auVar45 [12];
68: undefined auVar46 [13];
69: undefined auVar47 [16];
70: undefined auVar48 [16];
71: undefined auVar49 [16];
72: undefined auVar50 [16];
73: undefined auVar51 [16];
74: 
75: auVar60 = psllw(CONCAT214(0xffff,CONCAT212(0xffff,CONCAT210(0xffff,CONCAT28(0xffff,
76: 0xffffffffffffffff)))),7);
77: auVar60 = packsswb(auVar60,auVar60);
78: lVar7 = 4;
79: do {
80: uVar15 = *(ulong *)(*param_1 + (param_2 & 0xffffffff));
81: uVar41 = *(ulong *)(param_1[1] + (param_2 & 0xffffffff));
82: bVar8 = (char)uVar15 - SUB161(auVar60,0);
83: cVar61 = SUB161(auVar60 >> 8,0);
84: sVar26 = CONCAT11((char)(uVar15 >> 8) - cVar61,bVar8);
85: cVar62 = SUB161(auVar60 >> 0x10,0);
86: uVar10 = CONCAT12((char)(uVar15 >> 0x10) - cVar62,sVar26);
87: cVar63 = SUB161(auVar60 >> 0x18,0);
88: uVar11 = CONCAT13((char)(uVar15 >> 0x18) - cVar63,uVar10);
89: cVar53 = SUB161(auVar60 >> 0x20,0);
90: cVar27 = (char)(uVar15 >> 0x20) - cVar53;
91: uVar12 = CONCAT14(cVar27,uVar11);
92: cVar55 = SUB161(auVar60 >> 0x28,0);
93: cVar29 = (char)(uVar15 >> 0x28) - cVar55;
94: uVar13 = CONCAT15(cVar29,uVar12);
95: cVar56 = SUB161(auVar60 >> 0x30,0);
96: cVar30 = (char)((uVar15 & 0xffffff0000000000) >> 0x30) - cVar56;
97: uVar14 = CONCAT16(cVar30,uVar13);
98: cVar58 = SUB161(auVar60 >> 0x38,0);
99: cVar32 = (char)((uVar15 & 0xffffff0000000000) >> 0x38) - cVar58;
100: uVar15 = CONCAT17(cVar32,uVar14);
101: cVar64 = SUB161(auVar60 >> 0x40,0);
102: Var16 = CONCAT18(-cVar64,uVar15);
103: cVar65 = SUB161(auVar60 >> 0x48,0);
104: Var17 = CONCAT19(-cVar65,Var16);
105: cVar66 = SUB161(auVar60 >> 0x50,0);
106: auVar18 = CONCAT110(-cVar66,Var17);
107: cVar67 = SUB161(auVar60 >> 0x58,0);
108: auVar19 = CONCAT111(-cVar67,auVar18);
109: cVar68 = SUB161(auVar60 >> 0x60,0);
110: auVar20 = CONCAT112(-cVar68,auVar19);
111: cVar69 = SUB161(auVar60 >> 0x68,0);
112: bVar34 = (char)uVar41 - SUB161(auVar60,0);
113: sVar28 = CONCAT11((char)(uVar41 >> 8) - cVar61,bVar34);
114: uVar36 = CONCAT12((char)(uVar41 >> 0x10) - cVar62,sVar28);
115: uVar37 = CONCAT13((char)(uVar41 >> 0x18) - cVar63,uVar36);
116: cVar53 = (char)(uVar41 >> 0x20) - cVar53;
117: uVar38 = CONCAT14(cVar53,uVar37);
118: cVar55 = (char)(uVar41 >> 0x28) - cVar55;
119: uVar39 = CONCAT15(cVar55,uVar38);
120: cVar56 = (char)((uVar41 & 0xffffff0000000000) >> 0x30) - cVar56;
121: uVar40 = CONCAT16(cVar56,uVar39);
122: cVar58 = (char)((uVar41 & 0xffffff0000000000) >> 0x38) - cVar58;
123: uVar41 = CONCAT17(cVar58,uVar40);
124: Var42 = CONCAT18(-cVar64,uVar41);
125: Var43 = CONCAT19(-cVar65,Var42);
126: auVar44 = CONCAT110(-cVar66,Var43);
127: auVar45 = CONCAT111(-cVar67,auVar44);
128: auVar46 = CONCAT112(-cVar68,auVar45);
129: sVar33 = SUB162(CONCAT115(cVar32,CONCAT114(cVar32,CONCAT113(-cVar69,auVar20))) >> 0x70,0);
130: auVar25 = CONCAT313(SUB163(CONCAT214(sVar33,CONCAT113(cVar30,auVar20)) >> 0x68,0),
131: CONCAT112(cVar30,auVar19));
132: auVar24 = CONCAT511(SUB165(CONCAT412(SUB164(auVar25 >> 0x60,0),CONCAT111(cVar29,auVar18)) >>
133: 0x58,0),CONCAT110(cVar29,Var17));
134: auVar23 = CONCAT79(SUB167(CONCAT610(SUB166(auVar24 >> 0x50,0),CONCAT19(cVar27,Var16)) >> 0x48,0)
135: ,CONCAT18(cVar27,uVar15));
136: auVar22 = CONCAT97(SUB169(CONCAT88(SUB168(auVar23 >> 0x40,0),(uVar15 >> 0x18) << 0x38) >> 0x38,0
137: ),(uVar14 >> 0x18) << 0x30);
138: auVar21 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar22 >> 0x30,0),(uVar13 >> 0x10) << 0x28) >>
139: 0x28,0),(uVar12 >> 0x10) << 0x20);
140: uVar9 = (ushort)bVar8 | sVar26 << 8;
141: sVar59 = SUB162(CONCAT115(cVar58,CONCAT114(cVar58,CONCAT113(-cVar69,auVar46))) >> 0x70,0);
142: auVar51 = CONCAT313(SUB163(CONCAT214(sVar59,CONCAT113(cVar56,auVar46)) >> 0x68,0),
143: CONCAT112(cVar56,auVar45));
144: auVar50 = CONCAT511(SUB165(CONCAT412(SUB164(auVar51 >> 0x60,0),CONCAT111(cVar55,auVar44)) >>
145: 0x58,0),CONCAT110(cVar55,Var43));
146: auVar49 = CONCAT79(SUB167(CONCAT610(SUB166(auVar50 >> 0x50,0),CONCAT19(cVar53,Var42)) >> 0x48,0)
147: ,CONCAT18(cVar53,uVar41));
148: auVar48 = CONCAT97(SUB169(CONCAT88(SUB168(auVar49 >> 0x40,0),(uVar41 >> 0x18) << 0x38) >> 0x38,0
149: ),(uVar40 >> 0x18) << 0x30);
150: auVar47 = CONCAT115(SUB1611(CONCAT106(SUB1610(auVar48 >> 0x30,0),(uVar39 >> 0x10) << 0x28) >>
151: 0x28,0),(uVar38 >> 0x10) << 0x20);
152: uVar35 = (ushort)bVar34 | sVar28 << 8;
153: sVar31 = SUB162(auVar22 >> 0x30,0);
154: sVar28 = SUB162(auVar21 >> 0x20,0);
155: sVar26 = SUB162(CONCAT133(SUB1613(CONCAT124(SUB1612(auVar21 >> 0x20,0),(uVar11 >> 8) << 0x18) >>
156: 0x18,0),(uVar10 >> 8) << 0x10) >> 0x10,0);
157: sVar57 = SUB162(auVar48 >> 0x30,0);
158: sVar54 = SUB162(auVar47 >> 0x20,0);
159: sVar52 = SUB162(CONCAT133(SUB1613(CONCAT124(SUB1612(auVar47 >> 0x20,0),(uVar37 >> 8) << 0x18) >>
160: 0x18,0),(uVar36 >> 8) << 0x10) >> 0x10,0);
161: fVar1 = (float)CONCAT22(sVar26 >> 0xf,(short)((uint)(int)sVar26 >> 8));
162: fVar2 = (float)CONCAT22(sVar28 >> 0xf,(short)((uint)(int)sVar28 >> 8));
163: fVar3 = (float)CONCAT22(sVar31 >> 0xf,(short)((uint)(int)sVar31 >> 8));
164: fVar4 = (float)CONCAT22(sVar52 >> 0xf,(short)((uint)(int)sVar52 >> 8));
165: fVar5 = (float)CONCAT22(sVar54 >> 0xf,(short)((uint)(int)sVar54 >> 8));
166: fVar6 = (float)CONCAT22(sVar57 >> 0xf,(short)((uint)(int)sVar57 >> 8));
167: *param_3 = CONCAT214((short)((uint)fVar3 >> 0x10),
168: CONCAT212(SUB42(fVar3,0),
169: CONCAT210((short)((uint)fVar2 >> 0x10),
170: CONCAT28(SUB42(fVar2,0),
171: CONCAT26((short)((uint)fVar1 >> 0x10),
172: CONCAT24(SUB42(fVar1,0),
173: (float)CONCAT22((short)uVar9
174: >> 0xf,(
175: short)((uint)(int)(short)uVar9 >> 8))))))));
176: *(float *)param_3[1] = (float)((int)SUB162(auVar23 >> 0x40,0) >> 8);
177: *(float *)(param_3[1] + 4) = (float)((int)SUB162(auVar24 >> 0x50,0) >> 8);
178: *(float *)(param_3[1] + 8) = (float)((int)SUB162(auVar25 >> 0x60,0) >> 8);
179: *(float *)(param_3[1] + 0xc) = (float)((int)sVar33 >> 8);
180: param_3[2] = CONCAT214((short)((uint)fVar6 >> 0x10),
181: CONCAT212(SUB42(fVar6,0),
182: CONCAT210((short)((uint)fVar5 >> 0x10),
183: CONCAT28(SUB42(fVar5,0),
184: CONCAT26((short)((uint)fVar4 >> 0x10),
185: CONCAT24(SUB42(fVar4,0),
186: (float)CONCAT22((short)
187: uVar35 >> 0xf,
188: (short)((uint)(int)(short)uVar35 >> 8))))))));
189: *(float *)param_3[3] = (float)((int)SUB162(auVar49 >> 0x40,0) >> 8);
190: *(float *)(param_3[3] + 4) = (float)((int)SUB162(auVar50 >> 0x50,0) >> 8);
191: *(float *)(param_3[3] + 8) = (float)((int)SUB162(auVar51 >> 0x60,0) >> 8);
192: *(float *)(param_3[3] + 0xc) = (float)((int)sVar59 >> 8);
193: param_1 = param_1 + 2;
194: param_3 = param_3[4];
195: lVar7 = lVar7 + -1;
196: } while (lVar7 != 0);
197: return;
198: }
199: 
