1: 
2: void FUN_00113bf0(code **param_1,int param_2,int param_3)
3: 
4: {
5: code cVar1;
6: undefined8 *puVar2;
7: undefined *puVar3;
8: long *plVar4;
9: code **ppcVar5;
10: code *pcVar6;
11: int iVar7;
12: long lVar8;
13: code *pcVar9;
14: int iVar10;
15: code *pcVar11;
16: 
17: if (param_3 == 0) {
18: pcVar11 = param_1[(long)param_2 + 0x10];
19: }
20: else {
21: pcVar11 = param_1[(long)param_2 + 0x14];
22: param_2 = param_2 + 0x10;
23: }
24: if (pcVar11 == (code *)0x0) {
25: pcVar9 = *param_1;
26: *(int *)(pcVar9 + 0x2c) = param_2;
27: *(undefined4 *)(pcVar9 + 0x28) = 0x32;
28: (**(code **)*param_1)(param_1);
29: }
30: if (*(int *)(pcVar11 + 0x114) != 0) {
31: return;
32: }
33: puVar2 = (undefined8 *)param_1[5];
34: puVar3 = (undefined *)*puVar2;
35: *puVar2 = puVar3 + 1;
36: *puVar3 = 0xff;
37: lVar8 = puVar2[1];
38: puVar2[1] = lVar8 + -1;
39: if (lVar8 + -1 == 0) {
40: iVar10 = (*(code *)puVar2[3])(param_1);
41: if (iVar10 == 0) {
42: ppcVar5 = (code **)*param_1;
43: *(undefined4 *)(ppcVar5 + 5) = 0x18;
44: (**ppcVar5)(param_1);
45: }
46: }
47: puVar2 = (undefined8 *)param_1[5];
48: puVar3 = (undefined *)*puVar2;
49: *puVar2 = puVar3 + 1;
50: *puVar3 = 0xc4;
51: lVar8 = puVar2[1];
52: puVar2[1] = lVar8 + -1;
53: if (lVar8 + -1 == 0) {
54: iVar10 = (*(code *)puVar2[3])(param_1);
55: if (iVar10 == 0) {
56: ppcVar5 = (code **)*param_1;
57: *(undefined4 *)(ppcVar5 + 5) = 0x18;
58: (**ppcVar5)(param_1);
59: }
60: }
61: iVar10 = (uint)(byte)pcVar11[0x10] +
62: (uint)(byte)pcVar11[0xf] +
63: (uint)(byte)pcVar11[10] +
64: (uint)(byte)pcVar11[1] + (uint)(byte)pcVar11[2] + (uint)(byte)pcVar11[3] +
65: (uint)(byte)pcVar11[4] + (uint)(byte)pcVar11[5] + (uint)(byte)pcVar11[6] +
66: (uint)(byte)pcVar11[7] + (uint)(byte)pcVar11[8] + (uint)(byte)pcVar11[9] +
67: (uint)(byte)pcVar11[0xb] + (uint)(byte)pcVar11[0xc] + (uint)(byte)pcVar11[0xd] +
68: (uint)(byte)pcVar11[0xe];
69: plVar4 = (long *)param_1[5];
70: puVar3 = (undefined *)*plVar4;
71: *plVar4 = (long)(puVar3 + 1);
72: *puVar3 = (char)((uint)(iVar10 + 0x13) >> 8);
73: lVar8 = plVar4[1];
74: plVar4[1] = lVar8 + -1;
75: if (lVar8 + -1 == 0) {
76: iVar7 = (*(code *)plVar4[3])(param_1);
77: if (iVar7 == 0) {
78: ppcVar5 = (code **)*param_1;
79: *(undefined4 *)(ppcVar5 + 5) = 0x18;
80: (**ppcVar5)(param_1);
81: }
82: }
83: plVar4 = (long *)param_1[5];
84: puVar3 = (undefined *)*plVar4;
85: *plVar4 = (long)(puVar3 + 1);
86: *puVar3 = (char)(iVar10 + 0x13);
87: lVar8 = plVar4[1];
88: plVar4[1] = lVar8 + -1;
89: if (lVar8 + -1 == 0) {
90: iVar7 = (*(code *)plVar4[3])(param_1);
91: if (iVar7 == 0) {
92: ppcVar5 = (code **)*param_1;
93: *(undefined4 *)(ppcVar5 + 5) = 0x18;
94: (**ppcVar5)(param_1);
95: }
96: }
97: plVar4 = (long *)param_1[5];
98: puVar3 = (undefined *)*plVar4;
99: *plVar4 = (long)(puVar3 + 1);
100: *puVar3 = (char)param_2;
101: lVar8 = plVar4[1];
102: plVar4[1] = lVar8 + -1;
103: if (lVar8 + -1 == 0) {
104: iVar7 = (*(code *)plVar4[3])(param_1);
105: if (iVar7 == 0) {
106: ppcVar5 = (code **)*param_1;
107: *(undefined4 *)(ppcVar5 + 5) = 0x18;
108: (**ppcVar5)(param_1);
109: }
110: }
111: lVar8 = 0;
112: LAB_00113d9a:
113: do {
114: ppcVar5 = (code **)param_1[5];
115: cVar1 = pcVar11[lVar8 + 1];
116: pcVar9 = *ppcVar5;
117: *ppcVar5 = pcVar9 + 1;
118: *pcVar9 = cVar1;
119: pcVar9 = ppcVar5[1];
120: ppcVar5[1] = pcVar9 + -1;
121: if (pcVar9 + -1 == (code *)0x0) {
122: iVar7 = (*ppcVar5[3])(param_1);
123: if (iVar7 == 0) {
124: ppcVar5 = (code **)*param_1;
125: lVar8 = lVar8 + 1;
126: *(undefined4 *)(ppcVar5 + 5) = 0x18;
127: (**ppcVar5)(param_1);
128: if (lVar8 == 0x10) break;
129: goto LAB_00113d9a;
130: }
131: }
132: lVar8 = lVar8 + 1;
133: } while (lVar8 != 0x10);
134: if (iVar10 != 0) {
135: pcVar9 = pcVar11 + 0x11;
136: LAB_00113e09:
137: do {
138: ppcVar5 = (code **)param_1[5];
139: cVar1 = *pcVar9;
140: pcVar6 = *ppcVar5;
141: *ppcVar5 = pcVar6 + 1;
142: *pcVar6 = cVar1;
143: pcVar6 = ppcVar5[1];
144: ppcVar5[1] = pcVar6 + -1;
145: if (pcVar6 + -1 == (code *)0x0) {
146: iVar7 = (*ppcVar5[3])(param_1);
147: if (iVar7 == 0) {
148: ppcVar5 = (code **)*param_1;
149: pcVar9 = pcVar9 + 1;
150: *(undefined4 *)(ppcVar5 + 5) = 0x18;
151: (**ppcVar5)(param_1);
152: if (pcVar9 == pcVar11 + (ulong)(iVar10 - 1) + 0x12) break;
153: goto LAB_00113e09;
154: }
155: }
156: pcVar9 = pcVar9 + 1;
157: } while (pcVar9 != pcVar11 + (ulong)(iVar10 - 1) + 0x12);
158: }
159: *(undefined4 *)(pcVar11 + 0x114) = 1;
160: return;
161: }
162: 
