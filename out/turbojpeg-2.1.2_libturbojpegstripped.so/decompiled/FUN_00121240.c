1: 
2: undefined8 FUN_00121240(code **param_1,long param_2)
3: 
4: {
5: long *plVar1;
6: byte bVar2;
7: undefined4 uVar3;
8: uint uVar4;
9: code *pcVar5;
10: undefined8 uVar6;
11: code *pcVar7;
12: code **ppcVar8;
13: undefined8 *puVar9;
14: undefined *puVar10;
15: int iVar11;
16: uint uVar12;
17: uint uVar13;
18: int iVar14;
19: uint uVar15;
20: long lVar16;
21: uint uVar17;
22: long lVar18;
23: ulong uVar19;
24: uint uVar20;
25: ulong uVar21;
26: byte bStack92;
27: 
28: uVar3 = *(undefined4 *)(param_1 + 0x35);
29: pcVar5 = param_1[0x3e];
30: iVar11 = *(int *)(param_1 + 0x23);
31: uVar6 = *(undefined8 *)((long)param_1[5] + 8);
32: *(undefined8 *)(pcVar5 + 0x30) = *(undefined8 *)param_1[5];
33: *(undefined8 *)(pcVar5 + 0x38) = uVar6;
34: if ((iVar11 != 0) && (*(int *)(pcVar5 + 0x80) == 0)) {
35: FUN_00120fe0(pcVar5,*(undefined4 *)(pcVar5 + 0x84));
36: }
37: if (0 < *(int *)(param_1 + 0x2e)) {
38: lVar16 = 1;
39: do {
40: while( true ) {
41: lVar18 = (long)*(int *)((long)param_1 + lVar16 * 4 + 0x170);
42: bStack92 = (byte)uVar3;
43: pcVar7 = param_1[lVar18 + 0x29];
44: iVar11 = (int)**(short **)(param_2 + -8 + lVar16 * 8) >> (bStack92 & 0x1f);
45: uVar17 = iVar11 - *(int *)(pcVar5 + lVar18 * 4 + 0x58);
46: *(int *)(pcVar5 + lVar18 * 4 + 0x58) = iVar11;
47: uVar12 = (int)uVar17 >> 0x1f;
48: uVar17 = (uVar17 ^ uVar12) - uVar12;
49: bVar2 = (&DAT_0017cd40)[(int)uVar17];
50: uVar21 = (ulong)bVar2;
51: if (0xb < bVar2) {
52: ppcVar8 = (code **)*param_1;
53: *(undefined4 *)(ppcVar8 + 5) = 6;
54: (**ppcVar8)(param_1);
55: }
56: uVar20 = (uint)bVar2;
57: iVar11 = (int)lVar16;
58: if (*(int *)(pcVar5 + 0x28) == 0) break;
59: plVar1 = (long *)(*(long *)(pcVar5 + (long)*(int *)(pcVar7 + 0x14) * 8 + 0xa8) + uVar21 * 8)
60: ;
61: *plVar1 = *plVar1 + 1;
62: LAB_00121336:
63: if (uVar20 != 0) goto LAB_00121510;
64: LAB_0012133f:
65: lVar16 = lVar16 + 1;
66: if (*(int *)(param_1 + 0x2e) == iVar11 || *(int *)(param_1 + 0x2e) < iVar11)
67: goto LAB_00121355;
68: }
69: bVar2 = *(byte *)(*(long *)(pcVar5 + (long)*(int *)(pcVar7 + 0x14) * 8 + 0x88) + 0x400 +
70: (long)(int)uVar20);
71: uVar4 = *(uint *)(*(long *)(pcVar5 + (long)*(int *)(pcVar7 + 0x14) * 8 + 0x88) +
72: (long)(int)uVar20 * 4);
73: iVar14 = *(int *)(pcVar5 + 0x48);
74: if ((char)bVar2 == 0) {
75: ppcVar8 = (code **)**(code ***)(pcVar5 + 0x50);
76: *(undefined4 *)(ppcVar8 + 5) = 0x28;
77: (**ppcVar8)();
78: if (*(int *)(pcVar5 + 0x28) != 0) goto LAB_00121336;
79: }
80: uVar13 = iVar14 + (char)bVar2;
81: uVar19 = (ulong)(uVar4 & ~(uint)(-1 << (bVar2 & 0x3f))) << (0x18U - (char)uVar13 & 0x3f) |
82: *(ulong *)(pcVar5 + 0x40);
83: if (7 < (int)uVar13) {
84: uVar4 = uVar13 - 8;
85: uVar15 = uVar4 & 7;
86: do {
87: while( true ) {
88: uVar21 = uVar19;
89: puVar10 = *(undefined **)(pcVar5 + 0x30);
90: *(undefined **)(pcVar5 + 0x30) = puVar10 + 1;
91: *puVar10 = (char)(uVar21 >> 0x10);
92: plVar1 = (long *)(pcVar5 + 0x38);
93: *plVar1 = *plVar1 + -1;
94: if (*plVar1 == 0) {
95: puVar9 = *(undefined8 **)(*(long *)(pcVar5 + 0x50) + 0x28);
96: iVar14 = (*(code *)puVar9[3])();
97: if (iVar14 == 0) {
98: ppcVar8 = (code **)**(code ***)(pcVar5 + 0x50);
99: *(undefined4 *)(ppcVar8 + 5) = 0x18;
100: (**ppcVar8)();
101: }
102: *(undefined8 *)(pcVar5 + 0x30) = *puVar9;
103: *(undefined8 *)(pcVar5 + 0x38) = puVar9[1];
104: }
105: if (((uint)(uVar21 >> 0x10) & 0xff) == 0xff) break;
106: LAB_00121440:
107: uVar13 = uVar13 - 8;
108: uVar19 = uVar21 << 8;
109: if (uVar13 == uVar15) goto LAB_001214e0;
110: }
111: puVar10 = *(undefined **)(pcVar5 + 0x30);
112: *(undefined **)(pcVar5 + 0x30) = puVar10 + 1;
113: *puVar10 = 0;
114: plVar1 = (long *)(pcVar5 + 0x38);
115: *plVar1 = *plVar1 + -1;
116: if (*plVar1 != 0) goto LAB_00121440;
117: puVar9 = *(undefined8 **)(*(long *)(pcVar5 + 0x50) + 0x28);
118: iVar14 = (*(code *)puVar9[3])();
119: if (iVar14 == 0) {
120: ppcVar8 = (code **)**(code ***)(pcVar5 + 0x50);
121: *(undefined4 *)(ppcVar8 + 5) = 0x18;
122: (**ppcVar8)();
123: }
124: uVar13 = uVar13 - 8;
125: *(undefined8 *)(pcVar5 + 0x30) = *puVar9;
126: *(undefined8 *)(pcVar5 + 0x38) = puVar9[1];
127: uVar19 = uVar21 << 8;
128: } while (uVar13 != uVar15);
129: LAB_001214e0:
130: uVar19 = uVar21 << 8;
131: uVar21 = (ulong)uVar20;
132: uVar13 = uVar4 & 7;
133: }
134: *(ulong *)(pcVar5 + 0x40) = uVar19;
135: *(uint *)(pcVar5 + 0x48) = uVar13;
136: if ((int)uVar21 == 0) goto LAB_0012133f;
137: LAB_00121510:
138: FUN_001207a0(pcVar5,uVar12 ^ uVar17,uVar21);
139: lVar16 = lVar16 + 1;
140: } while (*(int *)(param_1 + 0x2e) != iVar11 && iVar11 <= *(int *)(param_1 + 0x2e));
141: }
142: LAB_00121355:
143: puVar9 = (undefined8 *)param_1[5];
144: *puVar9 = *(undefined8 *)(pcVar5 + 0x30);
145: puVar9[1] = *(undefined8 *)(pcVar5 + 0x38);
146: iVar11 = *(int *)(param_1 + 0x23);
147: if (iVar11 != 0) {
148: iVar14 = *(int *)(pcVar5 + 0x80);
149: if (*(int *)(pcVar5 + 0x80) == 0) {
150: *(uint *)(pcVar5 + 0x84) = *(int *)(pcVar5 + 0x84) + 1U & 7;
151: iVar14 = iVar11;
152: }
153: *(int *)(pcVar5 + 0x80) = iVar14 + -1;
154: }
155: return 1;
156: }
157: 
