1: 
2: int FUN_0011ca80(code **param_1,int param_2)
3: 
4: {
5: char **ppcVar1;
6: ushort uVar2;
7: ushort *puVar3;
8: code **ppcVar4;
9: undefined8 *puVar5;
10: long *plVar6;
11: char **ppcVar7;
12: char *pcVar8;
13: int iVar9;
14: ushort *puVar10;
15: long *plVar11;
16: undefined *puVar12;
17: undefined *puVar13;
18: int iVar14;
19: int *piVar15;
20: undefined uVar16;
21: 
22: puVar3 = (ushort *)param_1[(long)param_2 + 0xc];
23: if (puVar3 == (ushort *)0x0) {
24: ppcVar4 = (code **)*param_1;
25: *(undefined4 *)(ppcVar4 + 5) = 0x34;
26: *(int *)((long)ppcVar4 + 0x2c) = param_2;
27: (**ppcVar4)();
28: }
29: iVar14 = 0;
30: puVar10 = puVar3;
31: do {
32: if (0xff < *puVar10) {
33: iVar14 = 1;
34: }
35: puVar10 = puVar10 + 1;
36: } while (puVar3 + 0x40 != puVar10);
37: if (*(int *)(puVar3 + 0x40) == 0) {
38: puVar5 = (undefined8 *)param_1[5];
39: puVar12 = (undefined *)*puVar5;
40: *puVar5 = puVar12 + 1;
41: *puVar12 = 0xff;
42: plVar11 = puVar5 + 1;
43: *plVar11 = *plVar11 + -1;
44: if (*plVar11 == 0) {
45: iVar9 = (*(code *)puVar5[3])(param_1);
46: if (iVar9 == 0) {
47: ppcVar4 = (code **)*param_1;
48: *(undefined4 *)(ppcVar4 + 5) = 0x18;
49: (**ppcVar4)(param_1);
50: }
51: }
52: puVar5 = (undefined8 *)param_1[5];
53: puVar12 = (undefined *)*puVar5;
54: *puVar5 = puVar12 + 1;
55: *puVar12 = 0xdb;
56: plVar11 = puVar5 + 1;
57: *plVar11 = *plVar11 + -1;
58: if (*plVar11 == 0) {
59: iVar9 = (*(code *)puVar5[3])(param_1);
60: if (iVar9 == 0) {
61: ppcVar4 = (code **)*param_1;
62: *(undefined4 *)(ppcVar4 + 5) = 0x18;
63: (**ppcVar4)(param_1);
64: }
65: }
66: uVar16 = 0x83;
67: if (iVar14 == 0) {
68: uVar16 = 0x43;
69: }
70: puVar5 = (undefined8 *)param_1[5];
71: puVar12 = (undefined *)*puVar5;
72: *puVar5 = puVar12 + 1;
73: *puVar12 = 0;
74: plVar11 = puVar5 + 1;
75: *plVar11 = *plVar11 + -1;
76: if (*plVar11 == 0) {
77: iVar9 = (*(code *)puVar5[3])(param_1);
78: if (iVar9 == 0) {
79: ppcVar4 = (code **)*param_1;
80: *(undefined4 *)(ppcVar4 + 5) = 0x18;
81: (**ppcVar4)(param_1);
82: }
83: }
84: plVar6 = (long *)param_1[5];
85: puVar12 = (undefined *)*plVar6;
86: *plVar6 = (long)(puVar12 + 1);
87: *puVar12 = uVar16;
88: plVar11 = plVar6 + 1;
89: *plVar11 = *plVar11 + -1;
90: if (*plVar11 == 0) {
91: iVar9 = (*(code *)plVar6[3])(param_1);
92: if (iVar9 == 0) {
93: ppcVar4 = (code **)*param_1;
94: *(undefined4 *)(ppcVar4 + 5) = 0x18;
95: (**ppcVar4)(param_1);
96: }
97: }
98: ppcVar7 = (char **)param_1[5];
99: pcVar8 = *ppcVar7;
100: *ppcVar7 = pcVar8 + 1;
101: *pcVar8 = (char)param_2 + (char)(iVar14 << 4);
102: ppcVar1 = ppcVar7 + 1;
103: *ppcVar1 = *ppcVar1 + -1;
104: if (*ppcVar1 == (char *)0x0) {
105: iVar9 = (*(code *)ppcVar7[3])(param_1);
106: if (iVar9 == 0) {
107: ppcVar4 = (code **)*param_1;
108: *(undefined4 *)(ppcVar4 + 5) = 0x18;
109: (**ppcVar4)(param_1);
110: }
111: }
112: piVar15 = (int *)&DAT_0018f100;
113: do {
114: uVar2 = puVar3[*piVar15];
115: plVar11 = (long *)param_1[5];
116: puVar13 = (undefined *)*plVar11;
117: puVar12 = puVar13 + 1;
118: if (iVar14 != 0) {
119: *plVar11 = (long)puVar12;
120: *puVar13 = (char)(uVar2 >> 8);
121: plVar6 = plVar11 + 1;
122: *plVar6 = *plVar6 + -1;
123: if (*plVar6 == 0) {
124: iVar9 = (*(code *)plVar11[3])(param_1);
125: if (iVar9 == 0) {
126: ppcVar4 = (code **)*param_1;
127: *(undefined4 *)(ppcVar4 + 5) = 0x18;
128: (**ppcVar4)(param_1);
129: }
130: }
131: plVar11 = (long *)param_1[5];
132: puVar13 = (undefined *)*plVar11;
133: puVar12 = puVar13 + 1;
134: }
135: *plVar11 = (long)puVar12;
136: *puVar13 = (char)uVar2;
137: plVar6 = plVar11 + 1;
138: *plVar6 = *plVar6 + -1;
139: if (*plVar6 == 0) {
140: iVar9 = (*(code *)plVar11[3])(param_1);
141: if (iVar9 == 0) {
142: ppcVar4 = (code **)*param_1;
143: *(undefined4 *)(ppcVar4 + 5) = 0x18;
144: (**ppcVar4)(param_1);
145: }
146: }
147: piVar15 = piVar15 + 1;
148: } while (piVar15 != (int *)&UNK_0018f200);
149: *(undefined4 *)(puVar3 + 0x40) = 1;
150: }
151: return iVar14;
152: }
153: 
