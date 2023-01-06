1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void * tjLoadImage(char *param_1,int *param_2,uint param_3,int *param_4,int *param_5,uint param_6)
5: 
6: {
7: void **ppvVar1;
8: int iVar2;
9: int iVar3;
10: undefined4 uVar4;
11: uint uVar5;
12: uint uVar6;
13: long lVar7;
14: FILE *__fp;
15: int *piVar8;
16: char *pcVar9;
17: code **ppcVar10;
18: long lVar11;
19: bool bVar12;
20: int iVar13;
21: char *pcVar14;
22: long lVar15;
23: byte bVar16;
24: void *pvStack136;
25: 
26: bVar16 = 0;
27: if ((((param_1 == (char *)0x0) || (param_2 == (int *)0x0)) ||
28: (bVar12 = (int)param_3 < 1 || param_4 == (int *)0x0, bVar12)) ||
29: ((param_5 == (int *)0x0 || (0xc < *param_5 + 1U)))) {
30: s_No_error_003a6000._0_8_ = 0x6d4964616f4c6a74;
31: ram0x003a6008 = 0x49203a2928656761;
32: _DAT_003a6010 = 0x612064696c61766e;
33: _DAT_003a6018 = 0x746e656d756772;
34: }
35: else {
36: if ((param_3 & param_3 - 1) == 0) {
37: lVar7 = tjInitCompress();
38: if (lVar7 != 0) {
39: __fp = fopen(param_1,"rb");
40: if (__fp == (FILE *)0x0) {
41: piVar8 = __errno_location();
42: pcVar9 = strerror(*piVar8);
43: snprintf(s_No_error_003a6000,200,"%s\n%s","tjLoadImage(): Cannot open input file",pcVar9);
44: tjDestroy(lVar7);
45: return (void *)0x0;
46: }
47: iVar2 = _IO_getc((_IO_FILE *)__fp);
48: if ((iVar2 < 0) || (iVar3 = ungetc(iVar2,__fp), iVar3 == -1)) {
49: piVar8 = __errno_location();
50: pcVar9 = strerror(*piVar8);
51: snprintf(s_No_error_003a6000,200,"%s\n%s","tjLoadImage(): Could not read input file",
52: pcVar9);
53: pvStack136 = (void *)0x0;
54: }
55: else {
56: iVar3 = _setjmp((__jmp_buf_tag *)(lVar7 + 0x528));
57: pvStack136 = (void *)0x0;
58: if (iVar3 == 0) {
59: uVar4 = 0;
60: if (*param_5 != -1) {
61: uVar4 = *(undefined4 *)(&DAT_0018bb40 + (long)*param_5 * 4);
62: }
63: *(undefined4 *)(lVar7 + 0x3c) = uVar4;
64: if (iVar2 == 0x42) {
65: ppcVar10 = (code **)FUN_00151d30(lVar7,0);
66: uVar5 = (uint)((param_6 & 2) == 0);
67: }
68: else {
69: if (iVar2 != 0x50) {
70: _DAT_003a6020 = CONCAT35(DAT_003a6020_5,0x65707974);
71: s_No_error_003a6000._0_8_ = 0x6d4964616f4c6a74;
72: pvStack136 = (void *)0x0;
73: ram0x003a6008 = 0x55203a2928656761;
74: _DAT_003a6010 = 0x74726f707075736e;
75: _DAT_003a6018 = 0x20656c6966206465;
76: goto LAB_0014ad80;
77: }
78: ppcVar10 = (code **)FUN_00153cb0(lVar7);
79: uVar5 = param_6 >> 1 & 1;
80: }
81: if (ppcVar10 == (code **)0x0) {
82: lVar11 = 0x32;
83: pvStack136 = (void *)0x0;
84: pcVar9 = "tjLoadImage(): Could not initialize bitmap loader";
85: pcVar14 = s_No_error_003a6000;
86: while (lVar11 != 0) {
87: lVar11 = lVar11 + -1;
88: *pcVar14 = *pcVar9;
89: pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
90: pcVar14 = pcVar14 + (ulong)bVar16 * -2 + 1;
91: }
92: }
93: else {
94: ppcVar10[3] = (code *)__fp;
95: (**ppcVar10)(lVar7,ppcVar10);
96: (**(code **)(*(long *)(lVar7 + 8) + 0x30))(lVar7);
97: uVar6 = *(uint *)(lVar7 + 0x3c);
98: *param_2 = *(int *)(lVar7 + 0x30);
99: *param_4 = *(int *)(lVar7 + 0x34);
100: iVar2 = *(int *)(&DAT_0018bae0 + (ulong)uVar6 * 4);
101: *param_5 = iVar2;
102: lVar11 = (long)(int)((param_3 - 1) +
103: *param_2 * *(int *)(&DAT_0018bc40 + (long)iVar2 * 4) & -param_3);
104: pvStack136 = malloc(*param_4 * lVar11);
105: if (pvStack136 == (void *)0x0) {
106: lVar11 = 0x29;
107: pcVar9 = "tjLoadImage(): Memory allocation failure";
108: pcVar14 = s_No_error_003a6000;
109: while (lVar11 != 0) {
110: lVar11 = lVar11 + -1;
111: *pcVar14 = *pcVar9;
112: pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
113: pcVar14 = pcVar14 + (ulong)bVar16 * -2 + 1;
114: }
115: }
116: else {
117: iVar2 = _setjmp((__jmp_buf_tag *)(lVar7 + 0x528));
118: if (iVar2 == 0) {
119: if (*(uint *)(lVar7 + 0x130) <= *(uint *)(lVar7 + 0x34) &&
120: *(uint *)(lVar7 + 0x34) != *(uint *)(lVar7 + 0x130)) {
121: do {
122: iVar2 = (*ppcVar10[1])(lVar7,ppcVar10);
123: if (0 < iVar2) {
124: if (uVar5 == 0) {
125: lVar15 = 0;
126: iVar3 = 0;
127: do {
128: iVar13 = *(int *)(lVar7 + 0x130) + iVar3;
129: iVar3 = iVar3 + 1;
130: ppvVar1 = (void **)(ppcVar10[4] + lVar15);
131: lVar15 = lVar15 + 8;
132: memcpy((void *)(iVar13 * lVar11 + (long)pvStack136),*ppvVar1,
133: (long)(*param_2 * *(int *)(&DAT_0018bc40 + (long)*param_5 * 4)));
134: } while (iVar2 != iVar3);
135: }
136: else {
137: lVar15 = 0;
138: iVar3 = 0;
139: do {
140: uVar6 = *(int *)(lVar7 + 0x130) + iVar3;
141: iVar3 = iVar3 + 1;
142: ppvVar1 = (void **)(ppcVar10[4] + lVar15);
143: lVar15 = lVar15 + 8;
144: memcpy((void *)((int)(~uVar6 + *param_4) * lVar11 + (long)pvStack136),
145: *ppvVar1,(long)(*param_2 *
146: *(int *)(&DAT_0018bc40 + (long)*param_5 * 4)));
147: } while (iVar2 != iVar3);
148: }
149: }
150: uVar6 = iVar2 + *(int *)(lVar7 + 0x130);
151: *(uint *)(lVar7 + 0x130) = uVar6;
152: } while (uVar6 <= *(uint *)(lVar7 + 0x34) && *(uint *)(lVar7 + 0x34) != uVar6);
153: }
154: (*ppcVar10[2])(lVar7,ppcVar10);
155: }
156: else {
157: bVar12 = true;
158: }
159: }
160: }
161: }
162: }
163: LAB_0014ad80:
164: tjDestroy(lVar7);
165: fclose(__fp);
166: if (bVar12) {
167: free(pvStack136);
168: return (void *)0x0;
169: }
170: return pvStack136;
171: }
172: }
173: else {
174: _DAT_003a6028 = 0x20666f20;
175: s_No_error_003a6000._0_8_ = 0x6d4964616f4c6a74;
176: _DAT_003a602c = 0x32;
177: ram0x003a6008 = 0x41203a2928656761;
178: _DAT_003a6010 = 0x746e656d6e67696c;
179: _DAT_003a6018 = 0x6562207473756d20;
180: _DAT_003a6020 = 0x7265776f70206120;
181: }
182: }
183: return (void *)0x0;
184: }
185: 
