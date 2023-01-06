1: 
2: void * tjLoadImage(char *param_1,int *param_2,uint param_3,int *param_4,int *param_5,uint param_6)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: uint uVar5;
10: undefined4 *puVar6;
11: long lVar7;
12: FILE *__fp;
13: int *piVar8;
14: char *pcVar9;
15: undefined8 uVar10;
16: code **ppcVar11;
17: long lVar12;
18: char *pcVar13;
19: undefined4 uVar14;
20: int iVar15;
21: long lVar16;
22: byte bVar17;
23: undefined8 uVar18;
24: void *pvStack200;
25: int iStack160;
26: uint uStack68;
27: 
28: bVar17 = 0;
29: iStack160 = 0;
30: pvStack200 = (void *)0x0;
31: if ((((param_1 == (char *)0x0) || (param_2 == (int *)0x0)) ||
32: ((int)param_3 < 1 || param_4 == (int *)0x0)) ||
33: ((param_5 == (int *)0x0 || (0xc < *param_5 + 1U)))) {
34: puVar6 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
35: *puVar6 = 0x6f4c6a74;
36: puVar6[1] = 0x6d496461;
37: puVar6[2] = 0x28656761;
38: puVar6[3] = 0x49203a29;
39: puVar6[4] = 0x6c61766e;
40: puVar6[5] = 0x61206469;
41: puVar6[6] = 0x6d756772;
42: puVar6[7] = 0x746e65;
43: }
44: else {
45: if ((param_3 & param_3 - 1) == 0) {
46: lVar7 = tjInitCompress();
47: if (lVar7 == 0) {
48: return (void *)0x0;
49: }
50: __fp = fopen(param_1,"rb");
51: if (__fp == (FILE *)0x0) {
52: piVar8 = __errno_location();
53: pcVar9 = strerror(*piVar8);
54: uVar18 = 0x1591db;
55: uVar10 = __tls_get_addr(&PTR_00398fc0);
56: pcVar13 = "tjLoadImage(): Cannot open input file";
57: LAB_0015916e:
58: __snprintf_chk(uVar10,200,1,200,"%s\n%s",pcVar13,pcVar9,uVar18);
59: pvStack200 = (void *)0x0;
60: iStack160 = -1;
61: LAB_001590b8:
62: tjDestroy(lVar7);
63: }
64: else {
65: iVar3 = _IO_getc((_IO_FILE *)__fp);
66: if ((iVar3 < 0) || (iVar4 = ungetc(iVar3,__fp), iVar4 == -1)) {
67: piVar8 = __errno_location();
68: pcVar9 = strerror(*piVar8);
69: uVar18 = 0x15915b;
70: uVar10 = __tls_get_addr(&PTR_00398fc0);
71: pcVar13 = "tjLoadImage(): Could not read input file";
72: goto LAB_0015916e;
73: }
74: iVar4 = _setjmp((__jmp_buf_tag *)(lVar7 + 0x528));
75: if (iVar4 == 0) {
76: uVar14 = 0;
77: if (*param_5 != -1) {
78: uVar14 = *(undefined4 *)(&DAT_0018fc80 + (long)*param_5 * 4);
79: }
80: *(undefined4 *)(lVar7 + 0x3c) = uVar14;
81: if (iVar3 == 0x42) {
82: ppcVar11 = (code **)FUN_00168a70(lVar7,0);
83: if (ppcVar11 != (code **)0x0) {
84: uStack68 = (uint)((param_6 & 2) == 0);
85: goto LAB_00159229;
86: }
87: LAB_0015947b:
88: pcVar13 = (char *)__tls_get_addr(&PTR_00398fc0);
89: lVar12 = 0x32;
90: pcVar9 = "tjLoadImage(): Could not initialize bitmap loader";
91: while (lVar12 != 0) {
92: lVar12 = lVar12 + -1;
93: *pcVar13 = *pcVar9;
94: pcVar9 = pcVar9 + (ulong)bVar17 * -2 + 1;
95: pcVar13 = pcVar13 + (ulong)bVar17 * -2 + 1;
96: }
97: iStack160 = -1;
98: }
99: else {
100: if (iVar3 == 0x50) {
101: ppcVar11 = (code **)FUN_0016ab60(lVar7);
102: if (ppcVar11 == (code **)0x0) goto LAB_0015947b;
103: uStack68 = param_6 >> 1 & 1;
104: LAB_00159229:
105: ppcVar11[3] = (code *)__fp;
106: (**ppcVar11)(lVar7,ppcVar11);
107: (**(code **)(*(long *)(lVar7 + 8) + 0x30))(lVar7);
108: uVar5 = *(uint *)(lVar7 + 0x3c);
109: *param_2 = *(int *)(lVar7 + 0x30);
110: *param_4 = *(int *)(lVar7 + 0x34);
111: iVar3 = *(int *)(&DAT_0018fc20 + (ulong)uVar5 * 4);
112: *param_5 = iVar3;
113: lVar12 = (long)(int)(-param_3 &
114: (param_3 - 1) +
115: *param_2 * *(int *)(&DAT_0018fd80 + (long)iVar3 * 4));
116: pvStack200 = malloc(*param_4 * lVar12);
117: if (pvStack200 == (void *)0x0) {
118: pcVar13 = (char *)__tls_get_addr(&PTR_00398fc0);
119: lVar12 = 0x29;
120: pcVar9 = "tjLoadImage(): Memory allocation failure";
121: while (lVar12 != 0) {
122: lVar12 = lVar12 + -1;
123: *pcVar13 = *pcVar9;
124: pcVar9 = pcVar9 + (ulong)bVar17 * -2 + 1;
125: pcVar13 = pcVar13 + (ulong)bVar17 * -2 + 1;
126: }
127: iStack160 = -1;
128: }
129: else {
130: iVar3 = _setjmp((__jmp_buf_tag *)(lVar7 + 0x528));
131: if (iVar3 != 0) goto LAB_001591f3;
132: if (*(uint *)(lVar7 + 0x130) <= *(uint *)(lVar7 + 0x34) &&
133: *(uint *)(lVar7 + 0x34) != *(uint *)(lVar7 + 0x130)) {
134: do {
135: iVar3 = (*ppcVar11[1])();
136: if (0 < iVar3) {
137: iVar4 = *(int *)(&DAT_0018fd80 + (long)*param_5 * 4);
138: iVar2 = *param_2;
139: if (uStack68 == 0) {
140: lVar16 = 0;
141: do {
142: iVar15 = (int)lVar16;
143: lVar1 = lVar16 * 8;
144: lVar16 = lVar16 + 1;
145: memcpy((void *)((*(int *)(lVar7 + 0x130) + iVar15) * lVar12 +
146: (long)pvStack200),*(void **)(ppcVar11[4] + lVar1),
147: (long)(iVar4 * iVar2));
148: } while (lVar16 != (ulong)(iVar3 - 1) + 1);
149: }
150: else {
151: lVar16 = 0;
152: do {
153: iVar15 = (int)lVar16;
154: lVar1 = lVar16 * 8;
155: lVar16 = lVar16 + 1;
156: memcpy((void *)((~(*(int *)(lVar7 + 0x130) + iVar15) + *param_4) * lVar12
157: + (long)pvStack200),*(void **)(ppcVar11[4] + lVar1),
158: (long)(iVar4 * iVar2));
159: } while ((ulong)(iVar3 - 1) + 1 != lVar16);
160: }
161: }
162: uVar5 = iVar3 + *(int *)(lVar7 + 0x130);
163: *(uint *)(lVar7 + 0x130) = uVar5;
164: } while (uVar5 < *(uint *)(lVar7 + 0x34));
165: }
166: (*ppcVar11[2])(lVar7,ppcVar11);
167: }
168: }
169: else {
170: puVar6 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
171: puVar6[8] = 0x65707974;
172: *(undefined *)(puVar6 + 9) = 0;
173: *puVar6 = 0x6f4c6a74;
174: puVar6[1] = 0x6d496461;
175: puVar6[2] = 0x28656761;
176: puVar6[3] = 0x55203a29;
177: iStack160 = -1;
178: puVar6[4] = 0x7075736e;
179: puVar6[5] = 0x74726f70;
180: puVar6[6] = 0x66206465;
181: puVar6[7] = 0x20656c69;
182: }
183: }
184: }
185: else {
186: LAB_001591f3:
187: iStack160 = -1;
188: }
189: if (lVar7 != 0) goto LAB_001590b8;
190: }
191: if (__fp != (FILE *)0x0) {
192: fclose(__fp);
193: }
194: if (iStack160 != -1) {
195: return pvStack200;
196: }
197: goto LAB_00158f72;
198: }
199: puVar6 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
200: *(undefined8 *)(puVar6 + 8) = 0x7265776f70206120;
201: puVar6[10] = 0x20666f20;
202: *puVar6 = 0x6f4c6a74;
203: puVar6[1] = 0x6d496461;
204: puVar6[2] = 0x28656761;
205: puVar6[3] = 0x41203a29;
206: *(undefined2 *)(puVar6 + 0xb) = 0x32;
207: puVar6[4] = 0x6e67696c;
208: puVar6[5] = 0x746e656d;
209: puVar6[6] = 0x73756d20;
210: puVar6[7] = 0x65622074;
211: }
212: pvStack200 = (void *)0x0;
213: LAB_00158f72:
214: free(pvStack200);
215: return (void *)0x0;
216: }
217: 
