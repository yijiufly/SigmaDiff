1: 
2: undefined8 FUN_00130cb0(long param_1,long *param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: undefined4 uVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: uint uVar7;
12: int iVar8;
13: undefined8 *puVar9;
14: sbyte sVar10;
15: int iVar11;
16: ulong uVar12;
17: int iVar13;
18: int iVar14;
19: byte bStack124;
20: int iStack108;
21: undefined8 uStack104;
22: undefined8 uStack96;
23: ulong uStack88;
24: int iStack80;
25: long lStack72;
26: 
27: uVar2 = *(undefined4 *)(param_1 + 0x218);
28: lVar4 = *(long *)(param_1 + 0x250);
29: iVar8 = *(int *)(param_1 + 0x210);
30: if ((*(int *)(param_1 + 0x170) == 0) || (*(int *)(lVar4 + 0x3c) != 0)) {
31: LAB_00130cf1:
32: if (*(int *)(lVar4 + 0x10) != 0) goto LAB_00130d0f;
33: }
34: else {
35: iVar14 = *(int *)(lVar4 + 0x20);
36: lVar5 = *(long *)(param_1 + 0x248);
37: if (iVar14 < 0) {
38: iVar14 = iVar14 + 7;
39: }
40: piVar1 = (int *)(lVar5 + 0x24);
41: *piVar1 = *piVar1 + (iVar14 >> 3);
42: *(undefined4 *)(lVar4 + 0x20) = 0;
43: iVar14 = (**(code **)(lVar5 + 0x10))();
44: if (iVar14 == 0) {
45: return 0;
46: }
47: if (0 < *(int *)(param_1 + 0x1b0)) {
48: memset((void *)(lVar4 + 0x2c),0,(long)*(int *)(param_1 + 0x1b0) * 4);
49: }
50: uVar3 = *(undefined4 *)(param_1 + 0x170);
51: *(undefined4 *)(lVar4 + 0x28) = 0;
52: *(undefined4 *)(lVar4 + 0x3c) = uVar3;
53: if (*(int *)(param_1 + 0x21c) != 0) goto LAB_00130cf1;
54: *(undefined4 *)(lVar4 + 0x10) = 0;
55: }
56: iStack108 = *(int *)(lVar4 + 0x28);
57: if (iStack108 == 0) {
58: puVar9 = *(undefined8 **)(param_1 + 0x28);
59: iVar14 = *(int *)(param_1 + 0x20c);
60: lVar5 = *param_2;
61: uVar12 = *(ulong *)(lVar4 + 0x18);
62: iVar11 = *(int *)(lVar4 + 0x20);
63: uStack104 = *puVar9;
64: uStack96 = puVar9[1];
65: lVar6 = *(long *)(lVar4 + 0x60);
66: lStack72 = param_1;
67: if (iVar14 <= iVar8) {
68: do {
69: if (iVar11 < 8) {
70: iVar11 = FUN_00125d30(&uStack104);
71: if (iVar11 == 0) {
72: return 0;
73: }
74: uVar12 = uStack88;
75: iVar11 = iStack80;
76: if (7 < iStack80) goto LAB_00130de3;
77: LAB_00130e63:
78: uVar7 = FUN_00125ea0(&uStack104);
79: uVar12 = uStack88;
80: iVar11 = iStack80;
81: if ((int)uVar7 < 0) {
82: return 0;
83: }
84: }
85: else {
86: LAB_00130de3:
87: uVar7 = *(uint *)(lVar6 + 0x128 + (uVar12 >> ((char)iVar11 - 8U & 0x3f) & 0xff) * 4);
88: iVar13 = (int)uVar7 >> 8;
89: if (8 < iVar13) goto LAB_00130e63;
90: uVar7 = uVar7 & 0xff;
91: iVar11 = iVar11 - iVar13;
92: }
93: iVar13 = (int)uVar7 >> 4;
94: uVar7 = uVar7 & 0xf;
95: if (uVar7 == 0) {
96: if (iVar13 != 0xf) {
97: iStack108 = 1 << ((byte)iVar13 & 0x1f);
98: if (iVar13 != 0) {
99: if ((iVar11 < iVar13) &&
100: (iVar8 = FUN_00125d30(&uStack104), uVar12 = uStack88, iVar11 = iStack80, iVar8 == 0
101: )) {
102: return 0;
103: }
104: iVar11 = iVar11 - iVar13;
105: iStack108 = (iStack108 - 1U & (uint)(uVar12 >> ((byte)iVar11 & 0x3f))) + iStack108;
106: }
107: iStack108 = iStack108 + -1;
108: puVar9 = *(undefined8 **)(param_1 + 0x28);
109: goto LAB_00130f8a;
110: }
111: iVar14 = iVar14 + 0xf;
112: }
113: else {
114: iVar14 = iVar14 + iVar13;
115: if ((iVar11 < (int)uVar7) &&
116: (iVar13 = FUN_00125d30(&uStack104), uVar12 = uStack88, iVar11 = iStack80, iVar13 == 0))
117: {
118: return 0;
119: }
120: iVar11 = iVar11 - uVar7;
121: sVar10 = (sbyte)uVar7;
122: uVar7 = (1 << sVar10) - 1U & (uint)(uVar12 >> ((byte)iVar11 & 0x3f));
123: if ((int)uVar7 < 1 << (sVar10 - 1U & 0x1f)) {
124: uVar7 = uVar7 + 1 + (-1 << sVar10);
125: }
126: bStack124 = (byte)uVar2;
127: *(short *)(lVar5 + (long)*(int *)(&DAT_0018b460 + (long)iVar14 * 4) * 2) =
128: (short)((long)(int)uVar7 << (bStack124 & 0x3f));
129: }
130: iVar14 = iVar14 + 1;
131: } while (iVar14 <= iVar8);
132: puVar9 = *(undefined8 **)(param_1 + 0x28);
133: }
134: LAB_00130f8a:
135: *puVar9 = uStack104;
136: puVar9[1] = uStack96;
137: *(ulong *)(lVar4 + 0x18) = uVar12;
138: *(int *)(lVar4 + 0x20) = iVar11;
139: }
140: else {
141: iStack108 = iStack108 + -1;
142: }
143: *(int *)(lVar4 + 0x28) = iStack108;
144: LAB_00130d0f:
145: *(int *)(lVar4 + 0x3c) = *(int *)(lVar4 + 0x3c) + -1;
146: return 1;
147: }
148: 
