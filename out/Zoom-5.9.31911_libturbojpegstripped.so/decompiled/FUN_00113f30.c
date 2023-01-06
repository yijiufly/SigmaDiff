1: 
2: int FUN_00113f30(code **param_1,int param_2)
3: 
4: {
5: ushort uVar1;
6: code *pcVar2;
7: undefined8 *puVar3;
8: undefined *puVar4;
9: char **ppcVar5;
10: char *pcVar6;
11: long *plVar7;
12: code **ppcVar8;
13: code *pcVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: int *piVar13;
18: 
19: pcVar2 = param_1[(long)param_2 + 0xc];
20: if (pcVar2 == (code *)0x0) {
21: pcVar9 = *param_1;
22: *(int *)(pcVar9 + 0x2c) = param_2;
23: *(undefined4 *)(pcVar9 + 0x28) = 0x34;
24: (**(code **)*param_1)();
25: }
26: lVar11 = 0;
27: iVar12 = 0;
28: do {
29: if (0xff < *(ushort *)(pcVar2 + lVar11)) {
30: iVar12 = 1;
31: }
32: lVar11 = lVar11 + 2;
33: } while (lVar11 != 0x80);
34: if (*(int *)(pcVar2 + 0x80) == 0) {
35: puVar3 = (undefined8 *)param_1[5];
36: puVar4 = (undefined *)*puVar3;
37: *puVar3 = puVar4 + 1;
38: *puVar4 = 0xff;
39: lVar11 = puVar3[1];
40: puVar3[1] = lVar11 + -1;
41: if (lVar11 + -1 == 0) {
42: iVar10 = (*(code *)puVar3[3])(param_1);
43: if (iVar10 == 0) {
44: ppcVar8 = (code **)*param_1;
45: *(undefined4 *)(ppcVar8 + 5) = 0x18;
46: (**ppcVar8)(param_1);
47: }
48: }
49: puVar3 = (undefined8 *)param_1[5];
50: puVar4 = (undefined *)*puVar3;
51: *puVar3 = puVar4 + 1;
52: *puVar4 = 0xdb;
53: lVar11 = puVar3[1];
54: puVar3[1] = lVar11 + -1;
55: if (lVar11 + -1 == 0) {
56: iVar10 = (*(code *)puVar3[3])(param_1);
57: if (iVar10 == 0) {
58: ppcVar8 = (code **)*param_1;
59: *(undefined4 *)(ppcVar8 + 5) = 0x18;
60: (**ppcVar8)(param_1);
61: }
62: }
63: puVar3 = (undefined8 *)param_1[5];
64: puVar4 = (undefined *)*puVar3;
65: *puVar3 = puVar4 + 1;
66: *puVar4 = 0;
67: lVar11 = puVar3[1];
68: puVar3[1] = lVar11 + -1;
69: if (lVar11 + -1 == 0) {
70: iVar10 = (*(code *)puVar3[3])(param_1);
71: if (iVar10 == 0) {
72: ppcVar8 = (code **)*param_1;
73: *(undefined4 *)(ppcVar8 + 5) = 0x18;
74: (**ppcVar8)(param_1);
75: }
76: }
77: ppcVar5 = (char **)param_1[5];
78: pcVar6 = *ppcVar5;
79: *ppcVar5 = pcVar6 + 1;
80: *pcVar6 = (-(iVar12 == 0) & 0xc0U) + 0x83;
81: pcVar6 = ppcVar5[1];
82: ppcVar5[1] = pcVar6 + -1;
83: if (pcVar6 + -1 == (char *)0x0) {
84: iVar10 = (*(code *)ppcVar5[3])(param_1);
85: if (iVar10 == 0) {
86: ppcVar8 = (code **)*param_1;
87: *(undefined4 *)(ppcVar8 + 5) = 0x18;
88: (**ppcVar8)(param_1);
89: }
90: }
91: ppcVar5 = (char **)param_1[5];
92: pcVar6 = *ppcVar5;
93: *ppcVar5 = pcVar6 + 1;
94: *pcVar6 = (char)param_2 + (char)(iVar12 << 4);
95: pcVar6 = ppcVar5[1];
96: ppcVar5[1] = pcVar6 + -1;
97: if (pcVar6 + -1 == (char *)0x0) {
98: iVar10 = (*(code *)ppcVar5[3])(param_1);
99: if (iVar10 == 0) {
100: ppcVar8 = (code **)*param_1;
101: *(undefined4 *)(ppcVar8 + 5) = 0x18;
102: (**ppcVar8)(param_1);
103: }
104: }
105: piVar13 = (int *)&DAT_0018b460;
106: LAB_00114089:
107: do {
108: uVar1 = *(ushort *)(pcVar2 + (long)*piVar13 * 2);
109: if (iVar12 != 0) {
110: plVar7 = (long *)param_1[5];
111: puVar4 = (undefined *)*plVar7;
112: *plVar7 = (long)(puVar4 + 1);
113: *puVar4 = (char)((ulong)uVar1 >> 8);
114: lVar11 = plVar7[1];
115: plVar7[1] = lVar11 + -1;
116: if (lVar11 + -1 == 0) {
117: iVar10 = (*(code *)plVar7[3])(param_1);
118: if (iVar10 == 0) {
119: ppcVar8 = (code **)*param_1;
120: *(undefined4 *)(ppcVar8 + 5) = 0x18;
121: (**ppcVar8)(param_1);
122: }
123: }
124: }
125: plVar7 = (long *)param_1[5];
126: puVar4 = (undefined *)*plVar7;
127: *plVar7 = (long)(puVar4 + 1);
128: *puVar4 = (char)uVar1;
129: lVar11 = plVar7[1];
130: plVar7[1] = lVar11 + -1;
131: if (lVar11 + -1 == 0) {
132: iVar10 = (*(code *)plVar7[3])(param_1);
133: if (iVar10 == 0) {
134: ppcVar8 = (code **)*param_1;
135: piVar13 = piVar13 + 1;
136: *(undefined4 *)(ppcVar8 + 5) = 0x18;
137: (**ppcVar8)(param_1);
138: if (piVar13 == (int *)&UNK_0018b560) break;
139: goto LAB_00114089;
140: }
141: }
142: piVar13 = piVar13 + 1;
143: } while (piVar13 != (int *)&UNK_0018b560);
144: *(undefined4 *)(pcVar2 + 0x80) = 1;
145: }
146: return iVar12;
147: }
148: 
