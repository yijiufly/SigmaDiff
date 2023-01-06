1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_00154420(code **param_1,long param_2)
5: 
6: {
7: byte *pbVar1;
8: int iVar2;
9: code **ppcVar3;
10: long *plVar4;
11: _IO_FILE *__fp;
12: code *pcVar5;
13: ulong uVar6;
14: size_t sVar7;
15: byte bVar8;
16: uint uVar9;
17: uint __c;
18: byte bVar10;
19: long lVar11;
20: uint uVar12;
21: long in_FS_OFFSET;
22: undefined8 uStack104;
23: undefined4 uStack96;
24: ulong uStack88;
25: undefined4 uStack80;
26: undefined2 uStack76;
27: long lStack64;
28: 
29: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
30: iVar2 = *(int *)(param_1 + 8);
31: if ((iVar2 - 6U < 10) || (iVar2 == 2)) {
32: bVar8 = (-(*(int *)((long)param_1 + 0x6c) == 0) & 0x10U) + 8;
33: bVar10 = ~-(*(int *)((long)param_1 + 0x6c) == 0) & 3;
34: lVar11 = (-(ulong)(*(int *)((long)param_1 + 0x6c) == 0) & 0xfffffffffffffd00) + 0x31a;
35: uVar12 = ~-(uint)(*(int *)((long)param_1 + 0x6c) == 0) & 0x100;
36: }
37: else {
38: if ((iVar2 == 4) || (iVar2 == 0x10)) {
39: bVar8 = 0x18;
40: bVar10 = 0;
41: lVar11 = 0x1a;
42: uVar12 = 0;
43: }
44: else {
45: bVar8 = 8;
46: bVar10 = 3;
47: lVar11 = 0x31a;
48: uVar12 = 0x100;
49: }
50: }
51: uStack96 = (uint)bVar8 << 0x10;
52: uStack76 = 0;
53: uVar6 = (ulong)*(uint *)(param_2 + 0x4c) * (ulong)*(uint *)((long)param_1 + 0x8c) + lVar11;
54: uStack80 = CONCAT13(bVar10,0x1a0000);
55: uStack96 = CONCAT31(uStack96._1_3_,1);
56: uStack88._0_5_ =
57: CONCAT14((char)(uVar6 >> 0x10),CONCAT13((char)(uVar6 >> 8),CONCAT12((char)uVar6,0x4d42)));
58: uStack88 = (uVar6 >> 0x18 & 0xff) << 0x28 | (ulong)(uint5)uStack88;
59: uStack104 = CONCAT26((short)*(uint *)((long)param_1 + 0x8c),
60: CONCAT15((char)((uint)*(undefined4 *)(param_1 + 0x11) >> 8),
61: CONCAT14((char)*(undefined4 *)(param_1 + 0x11),0xc)));
62: sVar7 = fwrite(&uStack88,1,0xe,*(FILE **)(param_2 + 0x20));
63: if (sVar7 != 0xe) {
64: ppcVar3 = (code **)*param_1;
65: *(undefined4 *)(ppcVar3 + 5) = 0x25;
66: (**ppcVar3)(param_1);
67: }
68: sVar7 = fwrite(&uStack104,1,0xc,*(FILE **)(param_2 + 0x20));
69: if (sVar7 != 0xc) {
70: ppcVar3 = (code **)*param_1;
71: *(undefined4 *)(ppcVar3 + 5) = 0x25;
72: (**ppcVar3)();
73: }
74: if (uVar12 == 0) goto LAB_00154646;
75: plVar4 = (long *)param_1[0x14];
76: __fp = *(_IO_FILE **)(param_2 + 0x20);
77: uVar9 = *(uint *)((long)param_1 + 0x9c);
78: if (plVar4 == (long *)0x0) {
79: __c = 0;
80: do {
81: _IO_putc(__c,__fp);
82: _IO_putc(__c,__fp);
83: uVar9 = __c + 1;
84: _IO_putc(__c,__fp);
85: __c = uVar9;
86: } while (uVar9 != 0x100);
87: joined_r0x001546ff:
88: if ((int)uVar12 < (int)uVar9) {
89: pcVar5 = *param_1;
90: *(uint *)(pcVar5 + 0x2c) = uVar9;
91: *(undefined4 *)(pcVar5 + 0x28) = 0x400;
92: (**(code **)*param_1)();
93: }
94: }
95: else {
96: if (*(int *)(param_1 + 0x12) == 3) {
97: if (0 < (int)uVar9) {
98: lVar11 = 0;
99: do {
100: _IO_putc((uint)*(byte *)(plVar4[2] + lVar11),__fp);
101: _IO_putc((uint)*(byte *)(plVar4[1] + lVar11),__fp);
102: pbVar1 = (byte *)(*plVar4 + lVar11);
103: lVar11 = lVar11 + 1;
104: _IO_putc((uint)*pbVar1,__fp);
105: } while ((int)lVar11 < (int)uVar9);
106: goto joined_r0x001546ff;
107: }
108: }
109: else {
110: lVar11 = 0;
111: if (0 < (int)uVar9) {
112: do {
113: _IO_putc((uint)*(byte *)(*plVar4 + lVar11),__fp);
114: _IO_putc((uint)*(byte *)(*plVar4 + lVar11),__fp);
115: pbVar1 = (byte *)(*plVar4 + lVar11);
116: lVar11 = lVar11 + 1;
117: _IO_putc((uint)*pbVar1,__fp);
118: } while ((int)lVar11 < (int)uVar9);
119: goto joined_r0x001546ff;
120: }
121: }
122: uVar9 = 0;
123: }
124: if ((int)uVar9 < (int)uVar12) {
125: do {
126: uVar9 = uVar9 + 1;
127: _IO_putc(0,__fp);
128: _IO_putc(0,__fp);
129: _IO_putc(0,__fp);
130: } while (uVar9 != uVar12);
131: }
132: LAB_00154646:
133: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
134: /* WARNING: Subroutine does not return */
135: __stack_chk_fail();
136: }
137: return;
138: }
139: 
