1: 
2: undefined8 FUN_00131170(code **param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: int iVar3;
8: undefined4 uVar5;
9: code *pcVar6;
10: code **ppcVar7;
11: undefined2 *puVar8;
12: long lVar9;
13: code *pcVar10;
14: int iVar11;
15: uint uVar12;
16: undefined8 *puVar13;
17: byte bVar14;
18: int iVar15;
19: long lVar16;
20: ulong uVar17;
21: int iVar18;
22: long lVar19;
23: byte bStack144;
24: undefined8 uStack136;
25: undefined8 uStack128;
26: undefined4 uStack120;
27: undefined8 uStack104;
28: undefined8 uStack96;
29: ulong uStack88;
30: int iStack80;
31: code **ppcStack72;
32: int iVar4;
33: 
34: uVar2 = *(undefined4 *)(param_1 + 0x43);
35: pcVar6 = param_1[0x4a];
36: if ((*(int *)(param_1 + 0x2e) == 0) || (*(int *)(pcVar6 + 0x3c) != 0)) {
37: LAB_001311af:
38: if (*(int *)(pcVar6 + 0x10) != 0) goto LAB_0013137f;
39: }
40: else {
41: iVar15 = *(int *)(pcVar6 + 0x20);
42: pcVar10 = param_1[0x49];
43: if (iVar15 < 0) {
44: iVar15 = iVar15 + 7;
45: }
46: piVar1 = (int *)(pcVar10 + 0x24);
47: *piVar1 = *piVar1 + (iVar15 >> 3);
48: *(undefined4 *)(pcVar6 + 0x20) = 0;
49: iVar15 = (**(code **)(pcVar10 + 0x10))();
50: if (iVar15 == 0) {
51: return 0;
52: }
53: if (0 < *(int *)(param_1 + 0x36)) {
54: memset(pcVar6 + 0x2c,0,(long)*(int *)(param_1 + 0x36) * 4);
55: }
56: iVar15 = *(int *)((long)param_1 + 0x21c);
57: uVar5 = *(undefined4 *)(param_1 + 0x2e);
58: *(undefined4 *)(pcVar6 + 0x28) = 0;
59: *(undefined4 *)(pcVar6 + 0x3c) = uVar5;
60: if (iVar15 != 0) goto LAB_001311af;
61: *(undefined4 *)(pcVar6 + 0x10) = 0;
62: }
63: uStack136 = *(undefined8 *)(pcVar6 + 0x28);
64: puVar13 = (undefined8 *)param_1[5];
65: ppcStack72 = param_1;
66: uVar17 = *(ulong *)(pcVar6 + 0x18);
67: iVar15 = *(int *)(pcVar6 + 0x20);
68: uStack104 = *puVar13;
69: uStack96 = puVar13[1];
70: uStack128 = *(undefined8 *)(pcVar6 + 0x30);
71: uStack120 = *(undefined4 *)(pcVar6 + 0x38);
72: if (0 < *(int *)(param_1 + 0x3c)) {
73: lVar16 = 0;
74: do {
75: lVar19 = (long)*(int *)((long)param_1 + lVar16 * 4 + 0x1e4);
76: puVar8 = *(undefined2 **)(param_2 + lVar16 * 8);
77: lVar9 = *(long *)(pcVar6 + (long)*(int *)(param_1[lVar19 + 0x37] + 0x14) * 8 + 0x40);
78: if (iVar15 < 8) {
79: iVar15 = FUN_00125d30(&uStack104);
80: if (iVar15 == 0) {
81: return 0;
82: }
83: uVar17 = uStack88;
84: iVar15 = iStack80;
85: if (7 < iStack80) goto LAB_001312f3;
86: LAB_0013131d:
87: uVar12 = FUN_00125ea0(&uStack104);
88: uVar17 = uStack88;
89: iVar15 = iStack80;
90: if ((int)uVar12 < 0) {
91: return 0;
92: }
93: }
94: else {
95: LAB_001312f3:
96: uVar12 = *(uint *)(lVar9 + 0x128 + (uVar17 >> ((char)iVar15 - 8U & 0x3f) & 0xff) * 4);
97: iVar18 = (int)uVar12 >> 8;
98: if (8 < iVar18) goto LAB_0013131d;
99: uVar12 = uVar12 & 0xff;
100: iVar15 = iVar15 - iVar18;
101: }
102: if (uVar12 == 0) {
103: LAB_00131260:
104: iVar18 = *(int *)((long)&uStack136 + lVar19 * 4 + 4);
105: if (-1 < iVar18) goto LAB_0013126d;
106: LAB_001313f0:
107: if ((int)uVar12 < -0x80000000 - iVar18) goto LAB_00131279;
108: }
109: else {
110: if ((iVar15 < (int)uVar12) &&
111: (iVar18 = FUN_00125d30(&uStack104), uVar17 = uStack88, iVar15 = iStack80, iVar18 == 0)) {
112: return 0;
113: }
114: iVar15 = iVar15 - uVar12;
115: bVar14 = (byte)uVar12;
116: uVar12 = (1 << (bVar14 & 0x1f)) - 1U & (uint)(uVar17 >> ((byte)iVar15 & 0x3f));
117: if ((int)uVar12 < 1 << (bVar14 - 1 & 0x1f)) {
118: uVar12 = uVar12 + 1 + (-1 << (bVar14 & 0x1f));
119: goto LAB_00131260;
120: }
121: iVar18 = *(int *)((long)&uStack136 + lVar19 * 4 + 4);
122: if (iVar18 < 0) goto LAB_001313f0;
123: LAB_0013126d:
124: if (0x7fffffff - iVar18 < (int)uVar12) {
125: LAB_00131279:
126: ppcVar7 = (code **)*param_1;
127: *(undefined4 *)(ppcVar7 + 5) = 6;
128: (**ppcVar7)(param_1);
129: }
130: }
131: bStack144 = (byte)uVar2;
132: iVar11 = (int)lVar16 + 1;
133: *(uint *)((long)&uStack136 + lVar19 * 4 + 4) = uVar12 + iVar18;
134: lVar16 = lVar16 + 1;
135: iVar3 = *(int *)(param_1 + 0x3c);
136: iVar4 = *(int *)(param_1 + 0x3c);
137: *puVar8 = (short)((long)(int)(uVar12 + iVar18) << (bStack144 & 0x3f));
138: } while (iVar4 != iVar11 && iVar11 <= iVar3);
139: puVar13 = (undefined8 *)param_1[5];
140: }
141: *puVar13 = uStack104;
142: puVar13[1] = uStack96;
143: *(ulong *)(pcVar6 + 0x18) = uVar17;
144: *(int *)(pcVar6 + 0x20) = iVar15;
145: *(undefined8 *)(pcVar6 + 0x28) = uStack136;
146: *(undefined8 *)(pcVar6 + 0x30) = uStack128;
147: *(undefined4 *)(pcVar6 + 0x38) = uStack120;
148: LAB_0013137f:
149: *(int *)(pcVar6 + 0x3c) = *(int *)(pcVar6 + 0x3c) + -1;
150: return 1;
151: }
152: 
