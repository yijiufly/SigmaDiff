1: 
2: void FUN_0011b2f0(code **param_1,int param_2,uint param_3,undefined8 *param_4)
3: 
4: {
5: code cVar1;
6: code **ppcVar2;
7: undefined8 *puVar3;
8: long lVar4;
9: long lVar5;
10: ulong uVar6;
11: code *pcVar7;
12: long *plVar8;
13: undefined8 *puVar9;
14: int iVar10;
15: int iVar11;
16: int iVar12;
17: long lVar13;
18: ulong uVar14;
19: int iVar15;
20: uint uVar16;
21: long in_FS_OFFSET;
22: byte bVar17;
23: uint auStack1368 [258];
24: undefined8 uStack336;
25: undefined8 uStack328;
26: undefined auStack320 [256];
27: long lStack64;
28: 
29: bVar17 = 0;
30: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
31: if (3 < param_3) {
32: ppcVar2 = (code **)*param_1;
33: *(undefined4 *)(ppcVar2 + 5) = 0x32;
34: *(uint *)((long)ppcVar2 + 0x2c) = param_3;
35: (**ppcVar2)();
36: }
37: if (param_2 == 0) {
38: pcVar7 = param_1[(long)(int)param_3 + 0x14];
39: }
40: else {
41: pcVar7 = param_1[(long)(int)param_3 + 0x10];
42: }
43: if (pcVar7 == (code *)0x0) {
44: ppcVar2 = (code **)*param_1;
45: *(undefined4 *)(ppcVar2 + 5) = 0x32;
46: *(uint *)((long)ppcVar2 + 0x2c) = param_3;
47: (**ppcVar2)(param_1);
48: }
49: puVar3 = (undefined8 *)*param_4;
50: if (puVar3 == (undefined8 *)0x0) {
51: puVar3 = (undefined8 *)(**(code **)param_1[1])(param_1,1,0x500);
52: *param_4 = puVar3;
53: }
54: uVar14 = 1;
55: iVar15 = 0;
56: do {
57: cVar1 = pcVar7[uVar14];
58: uVar16 = (uint)(byte)cVar1;
59: if (0x100 < (int)(uVar16 + iVar15)) {
60: ppcVar2 = (code **)*param_1;
61: *(undefined4 *)(ppcVar2 + 5) = 8;
62: (**ppcVar2)(param_1);
63: }
64: if (cVar1 != (code)0x0) {
65: lVar5 = (long)iVar15;
66: plVar8 = (long *)(auStack320 + lVar5 + -8);
67: lVar4 = (uVar14 & 0xff) * 0x101010101010101;
68: if (uVar16 < 8) {
69: if (((byte)cVar1 & 4) == 0) {
70: if ((uVar16 != 0) && (*(char *)plVar8 = (char)lVar4, ((byte)cVar1 & 2) != 0)) {
71: *(short *)((long)&uStack336 + (ulong)uVar16 + lVar5 + 6) = (short)lVar4;
72: }
73: }
74: else {
75: *(int *)plVar8 = (int)lVar4;
76: *(int *)((long)&uStack336 + (ulong)uVar16 + lVar5 + 4) = (int)lVar4;
77: }
78: }
79: else {
80: *plVar8 = lVar4;
81: *(long *)((long)&uStack336 + (ulong)uVar16 + lVar5) = lVar4;
82: uVar6 = (ulong)(((int)plVar8 -
83: (int)(long *)((ulong)(auStack320 + lVar5) & 0xfffffffffffffff8)) + uVar16 >>
84: 3);
85: plVar8 = (long *)((ulong)(auStack320 + lVar5) & 0xfffffffffffffff8);
86: while (uVar6 != 0) {
87: uVar6 = uVar6 - 1;
88: *plVar8 = lVar4;
89: plVar8 = plVar8 + (ulong)bVar17 * -2 + 1;
90: }
91: }
92: iVar15 = iVar15 + uVar16;
93: }
94: uVar14 = uVar14 + 1;
95: } while (uVar14 != 0x11);
96: uVar16 = 0;
97: lVar4 = 0;
98: auStack320[(long)iVar15 + -8] = 0;
99: iVar10 = (int)(char)uStack328;
100: iVar11 = iVar10;
101: iVar12 = iVar10;
102: do {
103: if ((char)uStack328 == '\0') {
104: *puVar3 = 0;
105: puVar3[0x7f] = 0;
106: uVar14 = (ulong)(((int)puVar3 - (int)(undefined8 *)((ulong)(puVar3 + 1) & 0xfffffffffffffff8))
107: + 0x400U >> 3);
108: puVar9 = (undefined8 *)((ulong)(puVar3 + 1) & 0xfffffffffffffff8);
109: while (uVar14 != 0) {
110: uVar14 = uVar14 - 1;
111: *puVar9 = 0;
112: puVar9 = puVar9 + (ulong)bVar17 * -2 + 1;
113: }
114: puVar3[0x80] = 0;
115: puVar3[0x9f] = 0;
116: uVar14 = (ulong)(((int)puVar3 -
117: (int)(undefined8 *)((ulong)(puVar3 + 0x81) & 0xfffffffffffffff8)) + 0x500U >>
118: 3);
119: puVar9 = (undefined8 *)((ulong)(puVar3 + 0x81) & 0xfffffffffffffff8);
120: while (uVar14 != 0) {
121: uVar14 = uVar14 - 1;
122: *puVar9 = 0;
123: puVar9 = puVar9 + (ulong)bVar17 * -2 + 1;
124: }
125: if (iVar15 != 0) {
126: lVar4 = 0;
127: do {
128: uVar14 = (ulong)(byte)pcVar7[lVar4 + 0x11];
129: if (((-(uint)(param_2 == 0) & 0xf0) + 0xf < (uint)(byte)pcVar7[lVar4 + 0x11]) ||
130: (*(char *)((long)puVar3 + uVar14 + 0x400) != '\0')) {
131: ppcVar2 = (code **)*param_1;
132: *(undefined4 *)(ppcVar2 + 5) = 8;
133: (**ppcVar2)(param_1);
134: }
135: *(uint *)((long)puVar3 + uVar14 * 4) = auStack1368[lVar4];
136: lVar5 = lVar4 + -8;
137: lVar4 = lVar4 + 1;
138: *(undefined *)((long)puVar3 + uVar14 + 0x400) = auStack320[lVar5];
139: } while (lVar4 != (ulong)(iVar15 - 1) + 1);
140: }
141: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
142: return;
143: }
144: /* WARNING: Subroutine does not return */
145: __stack_chk_fail();
146: }
147: while (iVar12 != iVar10) {
148: if (1 << ((byte)iVar10 & 0x3f) <= (long)(ulong)uVar16) goto LAB_0011b4cc;
149: uVar16 = uVar16 * 2;
150: iVar10 = iVar10 + 1;
151: }
152: lVar5 = (long)((int)lVar4 + 1);
153: lVar13 = lVar4 - lVar5;
154: do {
155: iVar11 = (int)(char)auStack320[lVar5 + -8];
156: auStack1368[lVar13 + lVar5] = uVar16;
157: lVar4 = (long)(int)lVar5;
158: uVar16 = uVar16 + 1;
159: lVar5 = lVar5 + 1;
160: } while (iVar11 == iVar10);
161: iVar12 = iVar11;
162: if (1 << ((byte)iVar10 & 0x3f) <= (long)(ulong)uVar16) {
163: LAB_0011b4cc:
164: ppcVar2 = (code **)*param_1;
165: *(undefined4 *)(ppcVar2 + 5) = 8;
166: (**ppcVar2)(param_1);
167: lVar4 = (long)(int)lVar4;
168: }
169: uVar16 = uVar16 * 2;
170: iVar10 = iVar10 + 1;
171: uStack328._0_1_ = (char)iVar11;
172: } while( true );
173: }
174: 
