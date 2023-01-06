1: 
2: /* WARNING: Removing unreachable block (ram,0x00127ca9) */
3: 
4: undefined8 FUN_00127bf0(code **param_1,void **param_2,uint *param_3)
5: 
6: {
7: undefined4 *puVar1;
8: char *pcVar2;
9: undefined4 *puVar3;
10: uint uVar4;
11: long *plVar5;
12: code *pcVar6;
13: code **ppcVar7;
14: undefined4 uVar8;
15: undefined4 uVar9;
16: undefined4 uVar10;
17: long **pplVar11;
18: void *pvVar12;
19: undefined8 uVar13;
20: uint uVar14;
21: ulong uVar15;
22: long lVar16;
23: int iVar17;
24: uint uVar18;
25: undefined8 *puVar19;
26: char *pcVar20;
27: uint uVar21;
28: uint uVar22;
29: long **pplVar23;
30: long in_FS_OFFSET;
31: byte bVar24;
32: uint auStack2376 [256];
33: uint auStack1352 [256];
34: char acStack328 [2];
35: undefined2 uStack326;
36: undefined8 auStack324 [32];
37: long lStack64;
38: 
39: bVar24 = 0;
40: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
41: if ((param_2 == (void **)0x0) || (param_3 == (uint *)0x0)) {
42: ppcVar7 = (code **)*param_1;
43: *(undefined4 *)(ppcVar7 + 5) = 0x17;
44: (**ppcVar7)(param_1);
45: }
46: if (*(int *)((long)param_1 + 0x24) < 0xca) {
47: pcVar6 = *param_1;
48: *(int *)(pcVar6 + 0x2c) = *(int *)((long)param_1 + 0x24);
49: ppcVar7 = (code **)*param_1;
50: *(undefined4 *)(pcVar6 + 0x28) = 0x14;
51: (**ppcVar7)(param_1);
52: }
53: *param_2 = (void *)0x0;
54: uVar18 = 0xfe;
55: *param_3 = 0;
56: acStack328[1] = 0;
57: puVar19 = (undefined8 *)&uStack326;
58: if (((ulong)puVar19 & 2) != 0) {
59: puVar19 = auStack324;
60: uVar18 = 0xfc;
61: uStack326 = 0;
62: }
63: if (((ulong)puVar19 & 4) != 0) {
64: *(undefined4 *)puVar19 = 0;
65: uVar18 = uVar18 - 4;
66: puVar19 = (undefined8 *)((long)puVar19 + 4);
67: }
68: uVar15 = (ulong)(uVar18 >> 3);
69: while (uVar15 != 0) {
70: uVar15 = uVar15 - 1;
71: *puVar19 = 0;
72: puVar19 = puVar19 + (ulong)bVar24 * -2 + 1;
73: }
74: if ((uVar18 & 4) != 0) {
75: *(undefined4 *)puVar19 = 0;
76: puVar19 = (undefined8 *)((long)puVar19 + 4);
77: }
78: if ((uVar18 & 2) != 0) {
79: *(undefined2 *)puVar19 = 0;
80: }
81: pplVar23 = (long **)param_1[0x32];
82: uVar18 = 0;
83: pplVar11 = pplVar23;
84: if (pplVar23 != (long **)0x0) {
85: do {
86: while (((((*(char *)(pplVar11 + 1) == -0x1e &&
87: (uVar14 = *(uint *)(pplVar11 + 2), 0xd < uVar14)) &&
88: (plVar5 = pplVar11[3], *(char *)plVar5 == 'I')) &&
89: (((*(char *)((long)plVar5 + 1) == 'C' && (*(char *)((long)plVar5 + 2) == 'C')) &&
90: ((*(char *)((long)plVar5 + 3) == '_' &&
91: ((*(char *)((long)plVar5 + 4) == 'P' && (*(char *)((long)plVar5 + 5) == 'R'))))))))
92: && ((*(char *)((long)plVar5 + 6) == 'O' &&
93: ((((*(char *)((long)plVar5 + 7) == 'F' && (*(char *)(plVar5 + 1) == 'I')) &&
94: (*(char *)((long)plVar5 + 9) == 'L')) &&
95: ((*(char *)((long)plVar5 + 10) == 'E' && (*(char *)((long)plVar5 + 0xb) == '\0')))
96: )))))) {
97: if (uVar18 == 0) {
98: uVar18 = (uint)*(byte *)((long)plVar5 + 0xd);
99: }
100: else {
101: if (*(byte *)((long)plVar5 + 0xd) != uVar18) goto LAB_00127da0;
102: }
103: bVar24 = *(byte *)((long)plVar5 + 0xc);
104: uVar15 = (ulong)bVar24;
105: if (((uVar18 < bVar24) || (bVar24 == 0)) || (acStack328[uVar15] != '\0')) goto LAB_00127da0;
106: pplVar11 = (long **)*pplVar11;
107: acStack328[uVar15] = '\x01';
108: auStack2376[uVar15] = uVar14 - 0xe;
109: if (pplVar11 == (long **)0x0) goto LAB_00127d70;
110: }
111: pplVar11 = (long **)*pplVar11;
112: } while (pplVar11 != (long **)0x0);
113: LAB_00127d70:
114: if (uVar18 != 0) {
115: uVar14 = 0;
116: do {
117: if (*(char *)((long)register0x00000020 + -0x147 + (long)pplVar11) == '\0')
118: goto LAB_00127da0;
119: auStack1352[(long)pplVar11 + 1] = uVar14;
120: uVar14 = uVar14 + auStack2376[(long)pplVar11 + 1];
121: iVar17 = (int)pplVar11;
122: pplVar11 = (long **)((long)pplVar11 + 1);
123: } while (iVar17 + 2 <= (int)uVar18);
124: if (uVar14 != 0) {
125: pvVar12 = malloc((ulong)uVar14);
126: if (pvVar12 != (void *)0x0) goto LAB_00127e45;
127: pcVar6 = *param_1;
128: *(undefined4 *)(pcVar6 + 0x28) = 0x36;
129: *(undefined4 *)(pcVar6 + 0x2c) = 0xb;
130: (**(code **)*param_1)();
131: pplVar23 = (long **)param_1[0x32];
132: while (pplVar23 != (long **)0x0) {
133: LAB_00127e45:
134: if ((((*(char *)(pplVar23 + 1) == -0x1e) && (0xd < *(uint *)(pplVar23 + 2))) &&
135: (plVar5 = pplVar23[3], *(char *)plVar5 == 'I')) &&
136: (((((*(char *)((long)plVar5 + 1) == 'C' && (*(char *)((long)plVar5 + 2) == 'C')) &&
137: ((*(char *)((long)plVar5 + 3) == '_' &&
138: ((*(char *)((long)plVar5 + 4) == 'P' && (*(char *)((long)plVar5 + 5) == 'R'))))))
139: && (*(char *)((long)plVar5 + 6) == 'O')) &&
140: ((((*(char *)((long)plVar5 + 7) == 'F' && (*(char *)(plVar5 + 1) == 'I')) &&
141: (*(char *)((long)plVar5 + 9) == 'L')) &&
142: ((*(char *)((long)plVar5 + 10) == 'E' && (*(char *)((long)plVar5 + 0xb) == '\0'))))))
143: )) {
144: uVar4 = auStack2376[*(byte *)((long)plVar5 + 0xc)];
145: uVar18 = uVar4 - 1;
146: pcVar20 = (char *)((ulong)auStack1352[*(byte *)((long)plVar5 + 0xc)] + (long)pvVar12);
147: if (uVar4 != 0) {
148: if (((char *)((long)plVar5 + 0xeU) < pcVar20 + 0x10 &&
149: pcVar20 < (char *)((long)plVar5 + 0x1eU)) || (uVar4 < 0x10)) {
150: lVar16 = 0;
151: do {
152: pcVar20[lVar16] = *(char *)((long)plVar5 + lVar16 + 0xe);
153: lVar16 = lVar16 + 1;
154: } while (lVar16 != (ulong)uVar18 + 1);
155: }
156: else {
157: lVar16 = 0;
158: uVar22 = 0;
159: uVar21 = uVar4 & 0xfffffff0;
160: do {
161: puVar3 = (undefined4 *)((long)plVar5 + lVar16 + 0xe);
162: uVar8 = puVar3[1];
163: uVar9 = puVar3[2];
164: uVar10 = puVar3[3];
165: uVar22 = uVar22 + 1;
166: puVar1 = (undefined4 *)(pcVar20 + lVar16);
167: *puVar1 = *puVar3;
168: puVar1[1] = uVar8;
169: puVar1[2] = uVar9;
170: puVar1[3] = uVar10;
171: lVar16 = lVar16 + 0x10;
172: } while (uVar22 < uVar4 >> 4);
173: iVar17 = uVar18 - uVar21;
174: pcVar2 = (char *)((long)plVar5 + 0xeU) + uVar21;
175: pcVar20 = pcVar20 + uVar21;
176: if ((((((uVar4 != uVar21) && (*pcVar20 = *pcVar2, uVar18 != uVar21)) &&
177: (pcVar20[1] = pcVar2[1], iVar17 != 1)) &&
178: ((pcVar20[2] = pcVar2[2], iVar17 != 2 && (pcVar20[3] = pcVar2[3], iVar17 != 3))
179: )) && (pcVar20[4] = pcVar2[4], iVar17 != 4)) &&
180: (((((pcVar20[5] = pcVar2[5], iVar17 != 5 && (pcVar20[6] = pcVar2[6], iVar17 != 6)
181: ) && ((pcVar20[7] = pcVar2[7], iVar17 != 7 &&
182: (((pcVar20[8] = pcVar2[8], iVar17 != 8 &&
183: (pcVar20[9] = pcVar2[9], iVar17 != 9)) &&
184: (pcVar20[10] = pcVar2[10], iVar17 != 10)))))) &&
185: ((pcVar20[0xb] = pcVar2[0xb], iVar17 != 0xb &&
186: (pcVar20[0xc] = pcVar2[0xc], iVar17 != 0xc)))) &&
187: (pcVar20[0xd] = pcVar2[0xd], iVar17 != 0xd)))) {
188: pcVar20[0xe] = pcVar2[0xe];
189: }
190: }
191: }
192: }
193: pplVar23 = (long **)*pplVar23;
194: }
195: *param_2 = pvVar12;
196: uVar13 = 1;
197: *param_3 = uVar14;
198: goto LAB_00127db7;
199: }
200: LAB_00127da0:
201: pcVar6 = *param_1;
202: *(undefined4 *)(pcVar6 + 0x28) = 0x7f;
203: (**(code **)(pcVar6 + 8))(param_1,0xffffffff);
204: }
205: }
206: uVar13 = 0;
207: LAB_00127db7:
208: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
209: return uVar13;
210: }
211: /* WARNING: Subroutine does not return */
212: __stack_chk_fail();
213: }
214: 
