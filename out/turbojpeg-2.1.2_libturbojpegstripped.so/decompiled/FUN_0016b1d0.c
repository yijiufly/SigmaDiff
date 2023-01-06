1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0016b1d0(code **param_1,long param_2)
5: 
6: {
7: byte *pbVar1;
8: undefined4 uVar2;
9: code **ppcVar3;
10: long *plVar4;
11: _IO_FILE *__fp;
12: uint7 uVar5;
13: size_t sVar6;
14: undefined uVar8;
15: int iVar7;
16: uint uVar9;
17: uint uVar10;
18: long lVar11;
19: char cVar12;
20: uint uVar13;
21: long in_FS_OFFSET;
22: bool bVar14;
23: undefined2 uStack118;
24: undefined uStack116;
25: undefined uStack115;
26: undefined uStack114;
27: undefined uStack113;
28: undefined4 uStack112;
29: undefined uStack108;
30: byte bStack107;
31: undefined2 uStack106;
32: undefined auStack104 [7];
33: unkuint9 Stack97;
34: undefined auStack88 [16];
35: long lStack72;
36: long lStack64;
37: 
38: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
39: iVar7 = *(int *)(param_1 + 8);
40: if ((iVar7 - 6U < 10) || (iVar7 == 2)) {
41: lVar11 = (-(ulong)(*(int *)((long)param_1 + 0x6c) == 0) & 0xfffffffffffffc00) + 0x436;
42: bVar14 = *(int *)((long)param_1 + 0x6c) != 0;
43: cVar12 = (-(*(int *)((long)param_1 + 0x6c) == 0) & 0x10U) + 8;
44: bStack107 = ~-(*(int *)((long)param_1 + 0x6c) == 0) & 4;
45: uVar13 = ~-(uint)(*(int *)((long)param_1 + 0x6c) == 0) & 0x100;
46: }
47: else {
48: if ((iVar7 == 0x10) || (iVar7 == 4)) {
49: lVar11 = 0x36;
50: bVar14 = false;
51: cVar12 = '\x18';
52: bStack107 = 0;
53: uVar13 = 0;
54: }
55: else {
56: lVar11 = 0x436;
57: bVar14 = true;
58: cVar12 = '\b';
59: bStack107 = 4;
60: uVar13 = 0x100;
61: }
62: }
63: uVar10 = *(uint *)((long)param_1 + 0x8c);
64: uStack112 = 0;
65: uStack106 = 0;
66: uStack118 = 0x4d42;
67: uStack108 = 0x36;
68: uVar8 = (undefined)((ulong)uVar10 >> 8);
69: _auStack104 = CONCAT19(uVar8,SUB169((undefined  [16])0x0,0));
70: _auStack104 = CONCAT151(ZEXT915((unkuint9)((unkuint10)_auStack104 >> 8)),0x28);
71: auStack88 = (undefined  [16])0x0;
72: lVar11 = (ulong)*(uint *)(param_2 + 0x4c) * (ulong)uVar10 + lVar11;
73: uStack116 = (undefined)lVar11;
74: uStack115 = (undefined)((ulong)lVar11 >> 8);
75: uStack113 = (undefined)((ulong)lVar11 >> 0x18);
76: uVar2 = *(undefined4 *)(param_1 + 0x11);
77: uStack114 = (undefined)((ulong)lVar11 >> 0x10);
78: _auStack104 = ZEXT211(CONCAT11(uVar8,(char)uVar10)) << 0x40;
79: _auStack104 = CONCAT114(cVar12,ZEXT1314(CONCAT112(1,CONCAT111((char)(uVar10 >> 0x18),_auStack104))
80: ));
81: auStack104._0_6_ = CONCAT15((char)((uint)uVar2 >> 8),CONCAT14((char)uVar2,auStack104._0_4_));
82: uVar5 = SUB167(CONCAT106(SUB1510(_auStack104 >> 0x30,0),auStack104._0_6_),0);
83: _auStack104 = CONCAT110((char)(uVar10 >> 0x10),_auStack104);
84: _auStack104 = CONCAT511(SUB155(_auStack104 >> 0x58,0),_auStack104) &
85: (undefined  [16])0xffffffffffffffff;
86: if (*(char *)((long)param_1 + 0x17a) == '\x02') {
87: iVar7 = (uint)*(ushort *)((long)param_1 + 0x17c) * 100;
88: auStack88._0_11_ =
89: CONCAT110((char)((uint)iVar7 >> 0x10),
90: CONCAT19((char)((uint)iVar7 >> 8),SUB169((undefined  [16])0x0,0)));
91: iVar7 = (uint)*(ushort *)((long)param_1 + 0x17e) * 100;
92: auStack88 = ZEXT1516(CONCAT114((char)((uint)iVar7 >> 0x10),
93: CONCAT113((char)((uint)iVar7 >> 8),
94: CONCAT112((char)*(ushort *)((long)param_1 + 0x17e) *
95: 'd',ZEXT312(CONCAT21(SUB112(auStack88._0_11_
96: >> 0x48,0),
97: (char)*(ushort *)
98: ((long)param_1 +
99: 0x17c) * 'd')) <<
100: 0x40))));
101: }
102: lStack72 = (ulong)bVar14 << 8;
103: sVar6 = fwrite(&uStack118,1,0xe,*(FILE **)(param_2 + 0x20));
104: if (sVar6 != 0xe) {
105: ppcVar3 = (code **)*param_1;
106: *(undefined4 *)(ppcVar3 + 5) = 0x25;
107: (**ppcVar3)(param_1);
108: }
109: sVar6 = fwrite(auStack104,1,0x28,*(FILE **)(param_2 + 0x20));
110: if (sVar6 != 0x28) {
111: ppcVar3 = (code **)*param_1;
112: *(undefined4 *)(ppcVar3 + 5) = 0x25;
113: (**ppcVar3)();
114: }
115: if (uVar13 == 0) goto LAB_0016b4e0;
116: plVar4 = (long *)param_1[0x14];
117: __fp = *(_IO_FILE **)(param_2 + 0x20);
118: if (plVar4 == (long *)0x0) {
119: uVar10 = 0;
120: do {
121: _IO_putc(uVar10,__fp);
122: _IO_putc(uVar10,__fp);
123: uVar9 = uVar10 + 1;
124: _IO_putc(uVar10,__fp);
125: _IO_putc(0,__fp);
126: uVar10 = uVar9;
127: } while (uVar9 != 0x100);
128: LAB_0016b48d:
129: if ((int)uVar13 < (int)uVar9) {
130: param_1 = (code **)*param_1;
131: *(undefined4 *)(param_1 + 5) = 0x400;
132: *(uint *)((long)param_1 + 0x2c) = uVar9;
133: (**param_1)();
134: }
135: if ((int)uVar13 <= (int)uVar9) goto LAB_0016b4e0;
136: }
137: else {
138: uVar9 = *(uint *)((long)param_1 + 0x9c);
139: if (*(int *)(param_1 + 0x12) == 3) {
140: if (0 < (int)uVar9) {
141: lVar11 = 0;
142: do {
143: _IO_putc((uint)*(byte *)(plVar4[2] + lVar11),__fp);
144: _IO_putc((uint)*(byte *)(plVar4[1] + lVar11),__fp);
145: pbVar1 = (byte *)(*plVar4 + lVar11);
146: lVar11 = lVar11 + 1;
147: _IO_putc((uint)*pbVar1,__fp);
148: _IO_putc(0,__fp);
149: } while ((ulong)(uVar9 - 1) + 1 != lVar11);
150: goto LAB_0016b48d;
151: }
152: }
153: else {
154: if (0 < (int)uVar9) {
155: lVar11 = 0;
156: do {
157: _IO_putc((uint)*(byte *)(*plVar4 + lVar11),__fp);
158: _IO_putc((uint)*(byte *)(*plVar4 + lVar11),__fp);
159: pbVar1 = (byte *)(*plVar4 + lVar11);
160: lVar11 = lVar11 + 1;
161: _IO_putc((uint)*pbVar1,__fp);
162: _IO_putc(0,__fp);
163: } while ((ulong)(uVar9 - 1) + 1 != lVar11);
164: goto LAB_0016b48d;
165: }
166: }
167: uVar9 = 0;
168: }
169: do {
170: uVar9 = uVar9 + 1;
171: _IO_putc(0,__fp);
172: _IO_putc(0,__fp);
173: _IO_putc(0,__fp);
174: _IO_putc(0,__fp);
175: } while (uVar13 != uVar9);
176: LAB_0016b4e0:
177: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
178: /* WARNING: Subroutine does not return */
179: __stack_chk_fail();
180: }
181: return;
182: }
183: 
