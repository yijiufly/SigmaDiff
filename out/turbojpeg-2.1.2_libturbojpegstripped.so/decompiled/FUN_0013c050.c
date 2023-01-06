1: 
2: undefined8 FUN_0013c050(code **param_1,long param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: int iVar3;
8: code *pcVar4;
9: code **ppcVar5;
10: undefined2 *puVar6;
11: long lVar7;
12: code *pcVar8;
13: undefined8 uVar9;
14: undefined8 *puVar10;
15: byte bVar11;
16: int iVar12;
17: long lVar13;
18: ulong uVar14;
19: int iVar15;
20: long lVar16;
21: uint uVar17;
22: long in_FS_OFFSET;
23: byte bStack164;
24: int iStack140;
25: undefined8 uStack136;
26: undefined8 uStack128;
27: ulong uStack120;
28: int iStack112;
29: code **ppcStack104;
30: int iStack88;
31: int aiStack84 [5];
32: long lStack64;
33: 
34: iVar15 = *(int *)(param_1 + 0x2e);
35: pcVar4 = param_1[0x4a];
36: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
37: uVar2 = *(undefined4 *)(param_1 + 0x43);
38: if (iVar15 == 0) {
39: uVar9 = 1;
40: if (*(int *)(pcVar4 + 0x10) != 0) goto LAB_0013c0b1;
41: LAB_0013c0ec:
42: iStack140 = *(int *)(pcVar4 + 0x28);
43: LAB_0013c0f3:
44: puVar10 = (undefined8 *)param_1[5];
45: iStack88 = *(int *)(pcVar4 + 0x28);
46: uStack136 = *puVar10;
47: uStack128 = puVar10[1];
48: uVar14 = *(ulong *)(pcVar4 + 0x18);
49: iVar12 = *(int *)(pcVar4 + 0x20);
50: aiStack84[0] = *(int *)(pcVar4 + 0x2c);
51: aiStack84[1] = *(undefined4 *)(pcVar4 + 0x30);
52: aiStack84[2] = *(undefined4 *)(pcVar4 + 0x34);
53: aiStack84[3] = *(undefined4 *)(pcVar4 + 0x38);
54: ppcStack104 = param_1;
55: if (0 < *(int *)(param_1 + 0x3c)) {
56: lVar13 = 1;
57: do {
58: lVar16 = (long)*(int *)((long)param_1 + lVar13 * 4 + 0x1e0);
59: puVar6 = *(undefined2 **)(param_2 + -8 + lVar13 * 8);
60: lVar7 = *(long *)(pcVar4 + (long)*(int *)(param_1[lVar16 + 0x37] + 0x14) * 8 + 0x40);
61: if (iVar12 < 8) {
62: iVar15 = FUN_00130960(&uStack136);
63: if (iVar15 == 0) goto LAB_0013c2e8;
64: uVar14 = uStack120;
65: iVar12 = iStack112;
66: if (7 < iStack112) goto LAB_0013c220;
67: LAB_0013c284:
68: uVar17 = FUN_00130b10(&uStack136);
69: uVar14 = uStack120;
70: iVar12 = iStack112;
71: if ((int)uVar17 < 0) goto LAB_0013c2e8;
72: }
73: else {
74: LAB_0013c220:
75: uVar17 = *(uint *)(lVar7 + 0x128 + (uVar14 >> ((char)iVar12 - 8U & 0x3f) & 0xff) * 4);
76: iVar15 = (int)uVar17 >> 8;
77: if (8 < iVar15) goto LAB_0013c284;
78: uVar17 = uVar17 & 0xff;
79: iVar12 = iVar12 - iVar15;
80: }
81: if (uVar17 == 0) {
82: iVar15 = aiStack84[lVar16];
83: }
84: else {
85: if ((iVar12 < (int)uVar17) &&
86: (iVar15 = FUN_00130960(&uStack136), uVar14 = uStack120, iVar12 = iStack112, iVar15 == 0
87: )) goto LAB_0013c2e8;
88: iVar12 = iVar12 - uVar17;
89: bVar11 = (byte)uVar17;
90: uVar17 = (1 << (bVar11 & 0x1f)) - 1U & (uint)(uVar14 >> ((byte)iVar12 & 0x3f));
91: if ((int)uVar17 < 1 << (bVar11 - 1 & 0x1f)) {
92: uVar17 = uVar17 + 1 + (-1 << (bVar11 & 0x1f));
93: }
94: iVar3 = aiStack84[lVar16];
95: iVar15 = iVar3 + uVar17;
96: if (iVar3 < 0) {
97: if ((int)uVar17 < -0x80000000 - iVar3) goto LAB_0013c1af;
98: }
99: else {
100: if (0x7fffffff - iVar3 < (int)uVar17) {
101: LAB_0013c1af:
102: ppcVar5 = (code **)*param_1;
103: *(undefined4 *)(ppcVar5 + 5) = 6;
104: (**ppcVar5)(param_1);
105: }
106: }
107: }
108: bStack164 = (byte)uVar2;
109: aiStack84[lVar16] = iVar15;
110: *puVar6 = (short)((long)iVar15 << (bStack164 & 0x3f));
111: iVar15 = (int)lVar13;
112: lVar13 = lVar13 + 1;
113: } while (*(int *)(param_1 + 0x3c) != iVar15 && iVar15 <= *(int *)(param_1 + 0x3c));
114: puVar10 = (undefined8 *)param_1[5];
115: iVar15 = *(int *)(param_1 + 0x2e);
116: }
117: *puVar10 = uStack136;
118: puVar10[1] = uStack128;
119: *(ulong *)(pcVar4 + 0x18) = uVar14;
120: *(int *)(pcVar4 + 0x20) = iVar12;
121: iStack88 = iStack140;
122: *(int *)(pcVar4 + 0x28) = iStack140;
123: *(int *)(pcVar4 + 0x2c) = aiStack84[0];
124: *(int *)(pcVar4 + 0x30) = aiStack84[1];
125: *(int *)(pcVar4 + 0x34) = aiStack84[2];
126: *(int *)(pcVar4 + 0x38) = aiStack84[3];
127: LAB_0013c32c:
128: uVar9 = 1;
129: if (iVar15 == 0) goto LAB_0013c0b1;
130: }
131: else {
132: iStack140 = *(int *)(pcVar4 + 0x3c);
133: if (iStack140 == 0) {
134: iVar15 = *(int *)(pcVar4 + 0x20);
135: pcVar8 = param_1[0x49];
136: iVar12 = iVar15 + 7;
137: if (-1 < iVar15) {
138: iVar12 = iVar15;
139: }
140: piVar1 = (int *)(pcVar8 + 0x24);
141: *piVar1 = *piVar1 + (iVar12 >> 3);
142: *(undefined4 *)(pcVar4 + 0x20) = 0;
143: iVar15 = (**(code **)(pcVar8 + 0x10))();
144: if (iVar15 == 0) {
145: LAB_0013c2e8:
146: uVar9 = 0;
147: goto LAB_0013c0b1;
148: }
149: if (0 < *(int *)(param_1 + 0x36)) {
150: memset(pcVar4 + 0x2c,0,(ulong)(*(int *)(param_1 + 0x36) - 1) * 4 + 4);
151: }
152: iVar12 = *(int *)((long)param_1 + 0x21c);
153: iVar15 = *(int *)(param_1 + 0x2e);
154: *(undefined4 *)(pcVar4 + 0x28) = 0;
155: *(int *)(pcVar4 + 0x3c) = iVar15;
156: if (iVar12 == 0) {
157: *(undefined4 *)(pcVar4 + 0x10) = 0;
158: goto LAB_0013c0f3;
159: }
160: if (*(int *)(pcVar4 + 0x10) == 0) goto LAB_0013c0ec;
161: goto LAB_0013c32c;
162: }
163: if (*(int *)(pcVar4 + 0x10) == 0) goto LAB_0013c0ec;
164: }
165: *(int *)(pcVar4 + 0x3c) = *(int *)(pcVar4 + 0x3c) + -1;
166: uVar9 = 1;
167: LAB_0013c0b1:
168: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
169: /* WARNING: Subroutine does not return */
170: __stack_chk_fail();
171: }
172: return uVar9;
173: }
174: 
