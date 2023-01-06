1: 
2: /* WARNING: Could not reconcile some variable overlaps */
3: 
4: void FUN_0016ae80(code **param_1,long param_2)
5: 
6: {
7: byte *pbVar1;
8: int iVar2;
9: code **ppcVar3;
10: long *plVar4;
11: _IO_FILE *__fp;
12: size_t sVar5;
13: byte bVar6;
14: uint uVar7;
15: uint uVar8;
16: long lVar9;
17: uint uVar10;
18: long in_FS_OFFSET;
19: undefined8 uStack90;
20: undefined4 uStack82;
21: undefined2 uStack78;
22: undefined uStack76;
23: undefined uStack75;
24: undefined uStack74;
25: undefined uStack73;
26: undefined4 uStack72;
27: undefined uStack68;
28: byte bStack67;
29: undefined2 uStack66;
30: long lStack64;
31: 
32: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
33: iVar2 = *(int *)(param_1 + 8);
34: if ((iVar2 - 6U < 10) || (iVar2 == 2)) {
35: lVar9 = (-(ulong)(*(int *)((long)param_1 + 0x6c) == 0) & 0xfffffffffffffd00) + 0x31a;
36: bVar6 = (-(*(int *)((long)param_1 + 0x6c) == 0) & 0x10U) + 8;
37: bStack67 = ~-(*(int *)((long)param_1 + 0x6c) == 0) & 3;
38: uVar10 = ~-(uint)(*(int *)((long)param_1 + 0x6c) == 0) & 0x100;
39: }
40: else {
41: if ((iVar2 == 0x10) || (iVar2 == 4)) {
42: lVar9 = 0x1a;
43: bVar6 = 0x18;
44: bStack67 = 0;
45: uVar10 = 0;
46: }
47: else {
48: lVar9 = 0x31a;
49: bVar6 = 8;
50: bStack67 = 3;
51: uVar10 = 0x100;
52: }
53: }
54: uVar8 = *(uint *)((long)param_1 + 0x8c);
55: uStack82 = (uint)bVar6 << 0x10;
56: uStack72 = 0;
57: uStack78 = 0x4d42;
58: uStack68 = 0x1a;
59: uStack66 = 0;
60: lVar9 = (ulong)*(uint *)(param_2 + 0x4c) * (ulong)uVar8 + lVar9;
61: uStack82 = CONCAT31(uStack82._1_3_,1);
62: uStack76 = (undefined)lVar9;
63: uStack75 = (undefined)((ulong)lVar9 >> 8);
64: uStack73 = (undefined)((ulong)lVar9 >> 0x18);
65: uStack74 = (undefined)((ulong)lVar9 >> 0x10);
66: uStack90 = CONCAT26(CONCAT11((char)((ulong)uVar8 >> 8),(char)uVar8),
67: CONCAT15((char)((uint)*(undefined4 *)(param_1 + 0x11) >> 8),
68: CONCAT14((char)*(undefined4 *)(param_1 + 0x11),0xc)));
69: sVar5 = fwrite(&uStack78,1,0xe,*(FILE **)(param_2 + 0x20));
70: if (sVar5 != 0xe) {
71: ppcVar3 = (code **)*param_1;
72: *(undefined4 *)(ppcVar3 + 5) = 0x25;
73: (**ppcVar3)(param_1);
74: }
75: sVar5 = fwrite(&uStack90,1,0xc,*(FILE **)(param_2 + 0x20));
76: if (sVar5 != 0xc) {
77: ppcVar3 = (code **)*param_1;
78: *(undefined4 *)(ppcVar3 + 5) = 0x25;
79: (**ppcVar3)();
80: }
81: if (uVar10 == 0) goto LAB_0016b0e6;
82: plVar4 = (long *)param_1[0x14];
83: __fp = *(_IO_FILE **)(param_2 + 0x20);
84: if (plVar4 == (long *)0x0) {
85: uVar8 = 0;
86: do {
87: _IO_putc(uVar8,__fp);
88: _IO_putc(uVar8,__fp);
89: uVar7 = uVar8 + 1;
90: _IO_putc(uVar8,__fp);
91: uVar8 = uVar7;
92: } while (uVar7 != 0x100);
93: LAB_0016b0a3:
94: if ((int)uVar10 < (int)uVar7) {
95: param_1 = (code **)*param_1;
96: *(undefined4 *)(param_1 + 5) = 0x400;
97: *(uint *)((long)param_1 + 0x2c) = uVar7;
98: (**param_1)();
99: }
100: if ((int)uVar10 <= (int)uVar7) goto LAB_0016b0e6;
101: }
102: else {
103: uVar7 = *(uint *)((long)param_1 + 0x9c);
104: if (*(int *)(param_1 + 0x12) == 3) {
105: if (0 < (int)uVar7) {
106: lVar9 = 0;
107: do {
108: _IO_putc((uint)*(byte *)(plVar4[2] + lVar9),__fp);
109: _IO_putc((uint)*(byte *)(plVar4[1] + lVar9),__fp);
110: pbVar1 = (byte *)(*plVar4 + lVar9);
111: lVar9 = lVar9 + 1;
112: _IO_putc((uint)*pbVar1,__fp);
113: } while ((ulong)(uVar7 - 1) + 1 != lVar9);
114: goto LAB_0016b0a3;
115: }
116: }
117: else {
118: if (0 < (int)uVar7) {
119: lVar9 = 0;
120: do {
121: _IO_putc((uint)*(byte *)(*plVar4 + lVar9),__fp);
122: _IO_putc((uint)*(byte *)(*plVar4 + lVar9),__fp);
123: pbVar1 = (byte *)(*plVar4 + lVar9);
124: lVar9 = lVar9 + 1;
125: _IO_putc((uint)*pbVar1,__fp);
126: } while ((ulong)(uVar7 - 1) + 1 != lVar9);
127: goto LAB_0016b0a3;
128: }
129: }
130: uVar7 = 0;
131: }
132: do {
133: uVar7 = uVar7 + 1;
134: _IO_putc(0,__fp);
135: _IO_putc(0,__fp);
136: _IO_putc(0,__fp);
137: } while (uVar10 != uVar7);
138: LAB_0016b0e6:
139: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
140: /* WARNING: Subroutine does not return */
141: __stack_chk_fail();
142: }
143: return;
144: }
145: 
