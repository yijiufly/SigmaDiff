1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_00153fe0(code **param_1,long param_2)
5: 
6: {
7: byte *pbVar1;
8: undefined4 uVar2;
9: code **ppcVar3;
10: long *plVar4;
11: _IO_FILE *__fp;
12: code *pcVar5;
13: size_t sVar6;
14: char cVar7;
15: int iVar8;
16: ulong uVar9;
17: uint uVar10;
18: uint __c;
19: byte bVar11;
20: long lVar12;
21: uint uVar13;
22: long in_FS_OFFSET;
23: bool bVar14;
24: ulong uStack120;
25: undefined4 uStack112;
26: undefined2 uStack108;
27: undefined8 uStack104;
28: ulong uStack96;
29: undefined8 uStack88;
30: ulong uStack80;
31: long lStack72;
32: long lStack64;
33: 
34: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
35: iVar8 = *(int *)(param_1 + 8);
36: if ((iVar8 - 6U < 10) || (iVar8 == 2)) {
37: bVar14 = *(int *)((long)param_1 + 0x6c) != 0;
38: cVar7 = (-(*(int *)((long)param_1 + 0x6c) == 0) & 0x10U) + 8;
39: bVar11 = ~-(*(int *)((long)param_1 + 0x6c) == 0) & 4;
40: lVar12 = (-(ulong)(*(int *)((long)param_1 + 0x6c) == 0) & 0xfffffffffffffc00) + 0x436;
41: uVar13 = ~-(uint)(*(int *)((long)param_1 + 0x6c) == 0) & 0x100;
42: }
43: else {
44: if ((iVar8 == 4) || (iVar8 == 0x10)) {
45: bVar14 = false;
46: cVar7 = '\x18';
47: bVar11 = 0;
48: lVar12 = 0x36;
49: uVar13 = 0;
50: }
51: else {
52: bVar14 = true;
53: cVar7 = '\b';
54: bVar11 = 4;
55: lVar12 = 0x436;
56: uVar13 = 0x100;
57: }
58: }
59: uVar10 = *(uint *)((long)param_1 + 0x8c);
60: uStack88 = 0;
61: uStack80 = 0;
62: uStack112 = CONCAT13(bVar11,0x360000);
63: uStack96._0_4_ = uVar10 & 0xff;
64: uVar9 = (ulong)*(uint *)(param_2 + 0x4c) * (ulong)uVar10 + lVar12;
65: uStack96._0_7_ = CONCAT16(cVar7,(uint6)CONCAT14(1,(uint)uStack96));
66: uStack108 = 0;
67: uVar2 = *(undefined4 *)(param_1 + 0x11);
68: uStack120._0_5_ =
69: CONCAT14((char)(uVar9 >> 0x10),CONCAT13((char)(uVar9 >> 8),CONCAT12((char)uVar9,0x4d42)));
70: uStack120 = (uVar9 >> 0x18 & 0xff) << 0x28 | (ulong)(uint5)uStack120;
71: uStack104 = CONCAT17((char)((uint)uVar2 >> 0x18),
72: CONCAT16((char)((uint)uVar2 >> 0x10),
73: CONCAT15((char)((uint)uVar2 >> 8),CONCAT14((char)uVar2,0x28))));
74: uStack96._0_3_ =
75: CONCAT12((char)(uVar10 >> 0x10),CONCAT11((char)(uVar10 >> 8),(undefined)uStack96));
76: uStack96 = (ulong)(uint7)uStack96 & 0xffffffffffff0000 | (ulong)(uVar10 & 0xff000000) |
77: (ulong)(uint3)uStack96;
78: if (*(char *)((long)param_1 + 0x17a) == '\x02') {
79: uVar10 = (uint)*(ushort *)((long)param_1 + 0x17c) * 100;
80: uStack80._0_2_ = CONCAT11((char)(uVar10 >> 8),(char)*(ushort *)((long)param_1 + 0x17c) * 'd');
81: iVar8 = (uint)*(ushort *)((long)param_1 + 0x17e) * 100;
82: uStack80._0_6_ =
83: CONCAT15((char)((uint)iVar8 >> 8),
84: CONCAT14((char)*(ushort *)((long)param_1 + 0x17e) * 'd',
85: uVar10 & 0xffff0000 | (uint)(ushort)uStack80));
86: uStack80 = (ulong)CONCAT16((char)((uint)iVar8 >> 0x10),(undefined6)uStack80);
87: }
88: lStack72 = (ulong)bVar14 << 8;
89: sVar6 = fwrite(&uStack120,1,0xe,*(FILE **)(param_2 + 0x20));
90: if (sVar6 != 0xe) {
91: ppcVar3 = (code **)*param_1;
92: *(undefined4 *)(ppcVar3 + 5) = 0x25;
93: (**ppcVar3)(param_1);
94: }
95: sVar6 = fwrite(&uStack104,1,0x28,*(FILE **)(param_2 + 0x20));
96: if (sVar6 != 0x28) {
97: ppcVar3 = (code **)*param_1;
98: *(undefined4 *)(ppcVar3 + 5) = 0x25;
99: (**ppcVar3)();
100: }
101: if (uVar13 == 0) goto LAB_00154278;
102: plVar4 = (long *)param_1[0x14];
103: __fp = *(_IO_FILE **)(param_2 + 0x20);
104: uVar10 = *(uint *)((long)param_1 + 0x9c);
105: if (plVar4 == (long *)0x0) {
106: __c = 0;
107: do {
108: _IO_putc(__c,__fp);
109: _IO_putc(__c,__fp);
110: uVar10 = __c + 1;
111: _IO_putc(__c,__fp);
112: _IO_putc(0,__fp);
113: __c = uVar10;
114: } while (uVar10 != 0x100);
115: joined_r0x001543a1:
116: if ((int)uVar13 < (int)uVar10) {
117: pcVar5 = *param_1;
118: *(uint *)(pcVar5 + 0x2c) = uVar10;
119: *(undefined4 *)(pcVar5 + 0x28) = 0x400;
120: (**(code **)*param_1)();
121: }
122: }
123: else {
124: if (*(int *)(param_1 + 0x12) == 3) {
125: if (0 < (int)uVar10) {
126: lVar12 = 0;
127: do {
128: _IO_putc((uint)*(byte *)(plVar4[2] + lVar12),__fp);
129: _IO_putc((uint)*(byte *)(plVar4[1] + lVar12),__fp);
130: pbVar1 = (byte *)(*plVar4 + lVar12);
131: lVar12 = lVar12 + 1;
132: _IO_putc((uint)*pbVar1,__fp);
133: _IO_putc(0,__fp);
134: } while ((int)lVar12 < (int)uVar10);
135: goto joined_r0x001543a1;
136: }
137: }
138: else {
139: lVar12 = 0;
140: if (0 < (int)uVar10) {
141: do {
142: _IO_putc((uint)*(byte *)(*plVar4 + lVar12),__fp);
143: _IO_putc((uint)*(byte *)(*plVar4 + lVar12),__fp);
144: pbVar1 = (byte *)(*plVar4 + lVar12);
145: lVar12 = lVar12 + 1;
146: _IO_putc((uint)*pbVar1,__fp);
147: _IO_putc(0,__fp);
148: } while ((int)lVar12 < (int)uVar10);
149: goto joined_r0x001543a1;
150: }
151: }
152: uVar10 = 0;
153: }
154: if ((int)uVar10 < (int)uVar13) {
155: do {
156: uVar10 = uVar10 + 1;
157: _IO_putc(0,__fp);
158: _IO_putc(0,__fp);
159: _IO_putc(0,__fp);
160: _IO_putc(0,__fp);
161: } while (uVar10 != uVar13);
162: }
163: LAB_00154278:
164: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
165: /* WARNING: Subroutine does not return */
166: __stack_chk_fail();
167: }
168: return;
169: }
170: 
