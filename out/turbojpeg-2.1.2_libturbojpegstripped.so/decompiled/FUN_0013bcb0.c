1: 
2: undefined8 FUN_0013bcb0(long param_1,long *param_2)
3: 
4: {
5: int *piVar1;
6: undefined4 uVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: undefined8 uVar7;
12: sbyte sVar8;
13: undefined8 *puVar9;
14: int iVar10;
15: ulong uVar11;
16: int iVar12;
17: uint uVar13;
18: int iVar14;
19: long in_FS_OFFSET;
20: byte bStack112;
21: undefined8 uStack104;
22: undefined8 uStack96;
23: ulong uStack88;
24: int iStack80;
25: long lStack72;
26: long lStack64;
27: 
28: lVar3 = *(long *)(param_1 + 0x250);
29: iVar6 = *(int *)(param_1 + 0x210);
30: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
31: uVar2 = *(undefined4 *)(param_1 + 0x218);
32: iVar12 = *(int *)(param_1 + 0x170);
33: if (iVar12 == 0) {
34: if (*(int *)(lVar3 + 0x10) == 0) {
35: iVar12 = *(int *)(lVar3 + 0x28);
36: if (iVar12 == 0) goto LAB_0013bdcf;
37: *(int *)(lVar3 + 0x28) = iVar12 + -1;
38: }
39: }
40: else {
41: iVar14 = *(int *)(lVar3 + 0x3c);
42: if (iVar14 == 0) {
43: iVar12 = *(int *)(lVar3 + 0x20);
44: lVar4 = *(long *)(param_1 + 0x248);
45: iVar14 = iVar12 + 7;
46: if (-1 < iVar12) {
47: iVar14 = iVar12;
48: }
49: piVar1 = (int *)(lVar4 + 0x24);
50: *piVar1 = *piVar1 + (iVar14 >> 3);
51: *(undefined4 *)(lVar3 + 0x20) = 0;
52: iVar12 = (**(code **)(lVar4 + 0x10))();
53: if (iVar12 == 0) {
54: LAB_0013bf50:
55: uVar7 = 0;
56: goto LAB_0013bd13;
57: }
58: if (0 < *(int *)(param_1 + 0x1b0)) {
59: memset((void *)(lVar3 + 0x2c),0,(ulong)(*(int *)(param_1 + 0x1b0) - 1) * 4 + 4);
60: }
61: iVar14 = *(int *)(param_1 + 0x21c);
62: iVar12 = *(int *)(param_1 + 0x170);
63: *(undefined4 *)(lVar3 + 0x28) = 0;
64: *(int *)(lVar3 + 0x3c) = iVar12;
65: if (iVar14 == 0) {
66: *(undefined4 *)(lVar3 + 0x10) = 0;
67: LAB_0013bdcf:
68: puVar9 = *(undefined8 **)(param_1 + 0x28);
69: iVar14 = *(int *)(param_1 + 0x20c);
70: lVar4 = *param_2;
71: uVar11 = *(ulong *)(lVar3 + 0x18);
72: iVar10 = *(int *)(lVar3 + 0x20);
73: uStack104 = *puVar9;
74: uStack96 = puVar9[1];
75: lVar5 = *(long *)(lVar3 + 0x60);
76: lStack72 = param_1;
77: if (iVar6 < iVar14) {
78: iVar14 = 0;
79: }
80: else {
81: do {
82: if (iVar10 < 8) {
83: iVar12 = FUN_00130960(&uStack104);
84: if (iVar12 == 0) goto LAB_0013bf50;
85: uVar11 = uStack88;
86: iVar10 = iStack80;
87: if (7 < iStack80) goto LAB_0013be8d;
88: LAB_0013bf02:
89: uVar13 = FUN_00130b10(&uStack104);
90: uVar11 = uStack88;
91: iVar10 = iStack80;
92: if ((int)uVar13 < 0) goto LAB_0013bf50;
93: }
94: else {
95: LAB_0013be8d:
96: uVar13 = *(uint *)(lVar5 + 0x128 + (uVar11 >> ((char)iVar10 - 8U & 0x3f) & 0xff) * 4);
97: iVar12 = (int)uVar13 >> 8;
98: if (8 < iVar12) goto LAB_0013bf02;
99: uVar13 = uVar13 & 0xff;
100: iVar10 = iVar10 - iVar12;
101: }
102: iVar12 = (int)uVar13 >> 4;
103: uVar13 = uVar13 & 0xf;
104: if (uVar13 == 0) {
105: if (iVar12 != 0xf) {
106: iVar14 = 1 << ((byte)iVar12 & 0x1f);
107: if (iVar12 != 0) {
108: if ((iVar10 < iVar12) &&
109: (iVar6 = FUN_00130960(&uStack104), uVar11 = uStack88, iVar10 = iStack80,
110: iVar6 == 0)) goto LAB_0013bf50;
111: iVar10 = iVar10 - iVar12;
112: iVar14 = (iVar14 - 1U & (uint)(uVar11 >> ((byte)iVar10 & 0x3f))) + iVar14;
113: }
114: iVar14 = iVar14 + -1;
115: puVar9 = *(undefined8 **)(param_1 + 0x28);
116: iVar12 = *(int *)(param_1 + 0x170);
117: goto LAB_0013bf77;
118: }
119: iVar14 = iVar14 + 0xf;
120: }
121: else {
122: iVar14 = iVar14 + iVar12;
123: if ((iVar10 < (int)uVar13) &&
124: (iVar12 = FUN_00130960(&uStack104), uVar11 = uStack88, iVar10 = iStack80,
125: iVar12 == 0)) goto LAB_0013bf50;
126: iVar10 = iVar10 - uVar13;
127: sVar8 = (sbyte)uVar13;
128: uVar13 = (1 << sVar8) - 1U & (uint)(uVar11 >> ((byte)iVar10 & 0x3f));
129: if ((int)uVar13 < 1 << (sVar8 - 1U & 0x1f)) {
130: uVar13 = uVar13 + 1 + (-1 << sVar8);
131: }
132: bStack112 = (byte)uVar2;
133: *(short *)(lVar4 + (long)*(int *)(&DAT_0018f100 + (long)iVar14 * 4) * 2) =
134: (short)((long)(int)uVar13 << (bStack112 & 0x3f));
135: }
136: iVar14 = iVar14 + 1;
137: } while (iVar14 <= iVar6);
138: puVar9 = *(undefined8 **)(param_1 + 0x28);
139: iVar14 = 0;
140: iVar12 = *(int *)(param_1 + 0x170);
141: }
142: LAB_0013bf77:
143: *puVar9 = uStack104;
144: puVar9[1] = uStack96;
145: *(ulong *)(lVar3 + 0x18) = uVar11;
146: *(int *)(lVar3 + 0x20) = iVar10;
147: goto LAB_0013bf85;
148: }
149: if (*(int *)(lVar3 + 0x10) == 0) goto LAB_0013bdcf;
150: LAB_0013bf89:
151: if (iVar12 == 0) goto LAB_0013bd0e;
152: iVar14 = *(int *)(lVar3 + 0x3c);
153: }
154: else {
155: if (*(int *)(lVar3 + 0x10) == 0) {
156: iVar14 = *(int *)(lVar3 + 0x28) + -1;
157: if (*(int *)(lVar3 + 0x28) == 0) goto LAB_0013bdcf;
158: LAB_0013bf85:
159: *(int *)(lVar3 + 0x28) = iVar14;
160: goto LAB_0013bf89;
161: }
162: }
163: *(int *)(lVar3 + 0x3c) = iVar14 + -1;
164: }
165: LAB_0013bd0e:
166: uVar7 = 1;
167: LAB_0013bd13:
168: if (lStack64 != *(long *)(in_FS_OFFSET + 0x28)) {
169: /* WARNING: Subroutine does not return */
170: __stack_chk_fail();
171: }
172: return uVar7;
173: }
174: 
