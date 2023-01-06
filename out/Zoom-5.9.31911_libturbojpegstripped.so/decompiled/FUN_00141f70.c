1: 
2: ulong FUN_00141f70(long param_1)
3: 
4: {
5: int *piVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: long lVar5;
10: long lVar6;
11: int iVar7;
12: long lVar8;
13: ulong uVar9;
14: int iVar10;
15: int iVar11;
16: long lVar12;
17: int iVar13;
18: int iVar14;
19: int iVar15;
20: int iVar16;
21: int iVar17;
22: ulong uVar18;
23: uint uStack76;
24: int iStack60;
25: 
26: iVar14 = 1;
27: uVar9 = 0;
28: iVar3 = *(int *)(param_1 + 0x38);
29: uStack76 = 0xffffffff;
30: iVar2 = iVar3 + -1;
31: lVar5 = (ulong)(iVar3 - 2) * 0x60;
32: do {
33: iVar10 = *(int *)(&DAT_0018bc20 + uVar9 * 4);
34: uVar18 = uVar9 & 0xffffffff;
35: lVar8 = uVar9 * 4;
36: if ((iVar10 == iVar3) ||
37: (((*(int *)(param_1 + 0x3c) - 4U < 2 && (iVar10 == 3)) && (iVar3 == 4)))) {
38: lVar6 = *(long *)(param_1 + 0x130);
39: iVar7 = *(int *)(&DAT_0018bc90 + lVar8);
40: iVar4 = *(int *)(lVar6 + 8);
41: if (iVar7 < 0) {
42: iVar7 = iVar7 + 7;
43: }
44: iVar7 = iVar7 >> 3;
45: iVar17 = (int)uVar18;
46: if (iVar4 == iVar7) {
47: iVar11 = *(int *)(&DAT_0018bc70 + lVar8);
48: if (iVar11 < 0) {
49: iVar11 = iVar11 + 7;
50: }
51: if (*(int *)(lVar6 + 0xc) == iVar11 >> 3) {
52: if (iVar3 < 2) {
53: iVar11 = 0;
54: }
55: else {
56: if (*(int *)(param_1 + 0x3c) - 4U < 2) {
57: iVar11 = 0;
58: iVar16 = 1;
59: lVar12 = lVar6;
60: do {
61: iVar13 = 1;
62: if (iVar16 == 3) {
63: iVar13 = *(int *)(lVar6 + 0xc);
64: }
65: iVar15 = 1;
66: if (iVar16 == 3) {
67: iVar15 = iVar4;
68: }
69: if (*(int *)(lVar12 + 0x68) == iVar15) {
70: iVar11 = iVar11 + (uint)(*(int *)(lVar12 + 0x6c) == iVar13);
71: }
72: iVar16 = iVar16 + 1;
73: lVar12 = lVar12 + 0x60;
74: } while (iVar16 != iVar3);
75: }
76: else {
77: iVar11 = 0;
78: lVar12 = lVar6;
79: do {
80: if (*(int *)(lVar12 + 0x68) == 1) {
81: iVar11 = iVar11 + (uint)(*(int *)(lVar12 + 0x6c) == 1);
82: }
83: lVar12 = lVar12 + 0x60;
84: } while (lVar12 != lVar6 + 0x60 + lVar5);
85: }
86: }
87: if (iVar11 == iVar2) {
88: return uVar18;
89: }
90: }
91: }
92: if ((*(long *)(lVar6 + 8) == 0x200000002) && ((iVar17 == 4 || (iVar17 == 1)))) {
93: if (iVar3 < 2) {
94: iStack60 = 0;
95: }
96: else {
97: iVar11 = *(int *)(&DAT_0018bc70 + lVar8);
98: iVar16 = iVar11 + 7;
99: if (-1 < iVar11) {
100: iVar16 = iVar11;
101: }
102: if (*(int *)(param_1 + 0x3c) - 4U < 2) {
103: iVar11 = 1;
104: iStack60 = 0;
105: lVar8 = lVar6;
106: do {
107: iVar13 = 2;
108: if (iVar11 != 3) {
109: iVar13 = iVar7;
110: }
111: iVar15 = 2;
112: if (iVar11 != 3) {
113: iVar15 = iVar16 >> 3;
114: }
115: if (*(int *)(lVar8 + 0x68) == iVar15) {
116: iStack60 = iStack60 + (uint)(*(int *)(lVar8 + 0x6c) == iVar13);
117: }
118: iVar11 = iVar11 + 1;
119: lVar8 = lVar8 + 0x60;
120: } while (iVar11 != iVar3);
121: }
122: else {
123: iStack60 = 0;
124: lVar8 = lVar6 + 0x60 + lVar5;
125: lVar12 = lVar6;
126: do {
127: while (*(int *)(lVar12 + 0x68) != iVar16 >> 3) {
128: lVar12 = lVar12 + 0x60;
129: if (lVar12 == lVar8) goto LAB_001421d0;
130: }
131: piVar1 = (int *)(lVar12 + 0x6c);
132: lVar12 = lVar12 + 0x60;
133: iStack60 = iStack60 + (uint)(iVar7 == *piVar1);
134: } while (lVar12 != lVar8);
135: }
136: }
137: LAB_001421d0:
138: if (iStack60 == iVar2) {
139: return uVar18;
140: }
141: }
142: if (((int)(10 / (long)iVar10) < *(int *)(lVar6 + 0xc) * iVar4) || (iVar17 != 0))
143: goto joined_r0x001420b7;
144: if (1 < iVar3) {
145: lVar8 = lVar6 + 0x60;
146: iVar10 = 0;
147: do {
148: iVar10 = iVar10 + (uint)(*(long *)(lVar6 + 8) == *(long *)(lVar8 + 8));
149: if (iVar10 == iVar2) {
150: uStack76 = 0;
151: break;
152: }
153: lVar8 = lVar8 + 0x60;
154: } while (lVar8 != lVar6 + 0xc0 + lVar5);
155: }
156: }
157: else {
158: joined_r0x001420b7:
159: if (iVar14 == 6) {
160: return (ulong)uStack76;
161: }
162: }
163: uVar9 = uVar9 + 1;
164: iVar14 = iVar14 + 1;
165: } while( true );
166: }
167: 
