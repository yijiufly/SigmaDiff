1: 
2: /* WARNING: Removing unreachable block (ram,0x00111899) */
3: 
4: void FUN_00111780(code **param_1,int param_2,uint param_3,long *param_4)
5: 
6: {
7: char *pcVar1;
8: code cVar2;
9: char cVar3;
10: code *pcVar4;
11: code **ppcVar5;
12: code *pcVar6;
13: long lVar7;
14: ulong uVar8;
15: ulong uVar9;
16: int iVar10;
17: long lVar11;
18: int iVar12;
19: long lVar13;
20: undefined8 *puVar14;
21: undefined8 *puVar15;
22: int iVar16;
23: uint uVar17;
24: int iVar18;
25: int iVar19;
26: long in_FS_OFFSET;
27: bool bVar20;
28: byte bVar21;
29: int aiStack1368 [260];
30: char acStack328 [264];
31: long lStack64;
32: 
33: bVar21 = 0;
34: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
35: if (3 < param_3) {
36: pcVar4 = *param_1;
37: *(undefined4 *)(pcVar4 + 0x28) = 0x32;
38: *(uint *)(pcVar4 + 0x2c) = param_3;
39: (**(code **)*param_1)();
40: }
41: if (param_2 == 0) {
42: pcVar4 = param_1[(long)(int)param_3 + 0x14];
43: }
44: else {
45: pcVar4 = param_1[(long)(int)param_3 + 0x10];
46: }
47: if (pcVar4 == (code *)0x0) {
48: pcVar6 = *param_1;
49: *(undefined4 *)(pcVar6 + 0x28) = 0x32;
50: *(uint *)(pcVar6 + 0x2c) = param_3;
51: (**(code **)*param_1)();
52: lVar7 = *param_4;
53: }
54: else {
55: lVar7 = *param_4;
56: }
57: if (lVar7 == 0) {
58: lVar7 = (**(code **)param_1[1])(param_1,1,0x500);
59: *param_4 = lVar7;
60: }
61: lVar11 = 0;
62: iVar16 = 0;
63: do {
64: cVar2 = pcVar4[lVar11 + 1];
65: uVar17 = (uint)(byte)cVar2;
66: if (0x100 < (int)(iVar16 + uVar17)) {
67: ppcVar5 = (code **)*param_1;
68: *(undefined4 *)(ppcVar5 + 5) = 8;
69: (**ppcVar5)();
70: }
71: if (uVar17 != 0) {
72: lVar13 = (long)iVar16;
73: iVar16 = iVar16 + uVar17;
74: memset(acStack328 + lVar13,(int)lVar11 + 1,(ulong)(byte)cVar2);
75: }
76: lVar11 = lVar11 + 1;
77: } while (lVar11 != 0x10);
78: acStack328[iVar16] = '\0';
79: iVar18 = (int)acStack328[0];
80: if (acStack328[0] != '\0') {
81: uVar9 = 0;
82: lVar11 = 0;
83: iVar12 = iVar18;
84: LAB_001118a3:
85: while( true ) {
86: iVar10 = (int)lVar11 + 1;
87: aiStack1368[lVar11] = (int)uVar9;
88: uVar17 = (int)uVar9 + 1;
89: uVar9 = (ulong)uVar17;
90: cVar3 = acStack328[iVar10];
91: iVar19 = (int)cVar3;
92: if (iVar19 != iVar12) break;
93: lVar11 = (long)iVar10;
94: }
95: if (1 << ((byte)iVar18 & 0x3f) <= (long)uVar9) goto LAB_001118f1;
96: while (cVar3 != '\0') {
97: while( true ) {
98: uVar17 = uVar17 * 2;
99: iVar18 = iVar18 + 1;
100: uVar9 = (ulong)uVar17;
101: lVar11 = (long)iVar10;
102: iVar12 = iVar19;
103: if (iVar19 == iVar18) goto LAB_001118a3;
104: if ((long)uVar9 < 1 << ((byte)iVar18 & 0x3f)) break;
105: LAB_001118f1:
106: ppcVar5 = (code **)*param_1;
107: *(undefined4 *)(ppcVar5 + 5) = 8;
108: (**ppcVar5)();
109: if (cVar3 == '\0') goto LAB_00111924;
110: }
111: }
112: }
113: LAB_00111924:
114: puVar15 = (undefined8 *)(lVar7 + 0x400);
115: uVar9 = 0x100;
116: bVar20 = ((ulong)puVar15 & 1) != 0;
117: if (bVar20) {
118: *(undefined *)(lVar7 + 0x400) = 0;
119: puVar15 = (undefined8 *)(lVar7 + 0x401);
120: uVar9 = 0xff;
121: }
122: puVar14 = puVar15;
123: if (((ulong)puVar15 & 2) != 0) {
124: puVar14 = (undefined8 *)((long)puVar15 + 2);
125: uVar9 = (ulong)((int)uVar9 - 2);
126: *(undefined2 *)puVar15 = 0;
127: }
128: if (((ulong)puVar14 & 4) != 0) {
129: *(undefined4 *)puVar14 = 0;
130: uVar9 = (ulong)((int)uVar9 - 4);
131: puVar14 = (undefined8 *)((long)puVar14 + 4);
132: }
133: uVar8 = uVar9 >> 3;
134: while (uVar8 != 0) {
135: uVar8 = uVar8 - 1;
136: *puVar14 = 0;
137: puVar14 = puVar14 + (ulong)bVar21 * -2 + 1;
138: }
139: if ((uVar9 & 4) != 0) {
140: *(undefined4 *)puVar14 = 0;
141: puVar14 = (undefined8 *)((long)puVar14 + 4);
142: }
143: puVar15 = puVar14;
144: if ((uVar9 & 2) != 0) {
145: puVar15 = (undefined8 *)((long)puVar14 + 2);
146: *(undefined2 *)puVar14 = 0;
147: }
148: if (bVar20) {
149: *(undefined *)puVar15 = 0;
150: }
151: if (iVar16 != 0) {
152: lVar11 = 0;
153: do {
154: uVar9 = (ulong)(byte)pcVar4[lVar11 + 0x11];
155: if (((-(uint)(param_2 == 0) & 0xf0) + 0xf < (uint)(byte)pcVar4[lVar11 + 0x11]) ||
156: (*(char *)(lVar7 + 0x400 + uVar9) != '\0')) {
157: ppcVar5 = (code **)*param_1;
158: *(undefined4 *)(ppcVar5 + 5) = 8;
159: (**ppcVar5)(param_1);
160: }
161: *(int *)(lVar7 + uVar9 * 4) = aiStack1368[lVar11];
162: pcVar1 = acStack328 + lVar11;
163: lVar11 = lVar11 + 1;
164: *(char *)(lVar7 + 0x400 + uVar9) = *pcVar1;
165: } while (lVar11 != (ulong)(iVar16 - 1) + 1);
166: }
167: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
168: /* WARNING: Subroutine does not return */
169: __stack_chk_fail();
170: }
171: return;
172: }
173: 
