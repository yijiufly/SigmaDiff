1: 
2: /* WARNING: Type propagation algorithm not settling */
3: 
4: void FUN_0011ce30(code **param_1,int param_2,long param_3)
5: 
6: {
7: code *pcVar1;
8: code *pcVar2;
9: undefined8 *puVar3;
10: ulong uVar4;
11: int iVar5;
12: uint uVar6;
13: code **ppcVar8;
14: code **ppcVar9;
15: undefined8 *puVar10;
16: bool bVar11;
17: byte bVar12;
18: ulong uVar7;
19: 
20: bVar12 = 0;
21: param_1[1] = (code *)0x0;
22: if (param_2 != 0x3e) {
23: pcVar1 = *param_1;
24: *(undefined4 *)(pcVar1 + 0x2c) = 0x3e;
25: *(undefined4 *)(pcVar1 + 0x28) = 0xc;
26: *(int *)(*param_1 + 0x30) = param_2;
27: (**(code **)*param_1)();
28: }
29: if (param_3 != 0x278) {
30: pcVar1 = *param_1;
31: *(undefined4 *)(pcVar1 + 0x2c) = 0x278;
32: *(undefined4 *)(pcVar1 + 0x28) = 0x15;
33: *(int *)(*param_1 + 0x30) = (int)param_3;
34: (**(code **)*param_1)(param_1);
35: }
36: bVar11 = ((ulong)param_1 & 1) != 0;
37: pcVar1 = *param_1;
38: pcVar2 = param_1[3];
39: uVar7 = 0x278;
40: iVar5 = 0x278;
41: if (bVar11) {
42: *(undefined *)param_1 = 0;
43: uVar7 = 0x277;
44: iVar5 = 0x277;
45: uVar4 = (ulong)(code **)((long)param_1 + 1) & 2;
46: ppcVar8 = (code **)((long)param_1 + 1);
47: }
48: else {
49: uVar4 = (ulong)param_1 & 2;
50: ppcVar8 = param_1;
51: }
52: if (uVar4 == 0) {
53: uVar6 = (uint)uVar7;
54: }
55: else {
56: uVar6 = iVar5 - 2;
57: uVar7 = (ulong)uVar6;
58: *(undefined2 *)ppcVar8 = 0;
59: ppcVar8 = (code **)((long)ppcVar8 + 2);
60: }
61: if (((ulong)ppcVar8 & 4) != 0) {
62: *(undefined4 *)ppcVar8 = 0;
63: uVar7 = (ulong)(uVar6 - 4);
64: ppcVar8 = (code **)((long)ppcVar8 + 4);
65: }
66: uVar4 = uVar7 >> 3;
67: while (uVar4 != 0) {
68: uVar4 = uVar4 - 1;
69: *ppcVar8 = (code *)0x0;
70: ppcVar8 = ppcVar8 + (ulong)bVar12 * -2 + 1;
71: }
72: if ((uVar7 & 4) != 0) {
73: *(undefined4 *)ppcVar8 = 0;
74: ppcVar8 = (code **)((long)ppcVar8 + 4);
75: }
76: ppcVar9 = ppcVar8;
77: if ((uVar7 & 2) != 0) {
78: ppcVar9 = (code **)((long)ppcVar8 + 2);
79: *(undefined2 *)ppcVar8 = 0;
80: }
81: if (bVar11) {
82: *(undefined *)ppcVar9 = 0;
83: }
84: *param_1 = pcVar1;
85: param_1[3] = pcVar2;
86: *(undefined4 *)(param_1 + 4) = 1;
87: FUN_0013d740(param_1);
88: param_1[2] = (code *)0x0;
89: param_1[5] = (code *)0x0;
90: param_1[0x19] = (code *)0x0;
91: param_1[0x1a] = (code *)0x0;
92: param_1[0x1b] = (code *)0x0;
93: param_1[0x1c] = (code *)0x0;
94: param_1[0x1d] = (code *)0x0;
95: param_1[0x1e] = (code *)0x0;
96: param_1[0x1f] = (code *)0x0;
97: param_1[0x20] = (code *)0x0;
98: param_1[0x21] = (code *)0x0;
99: param_1[0x22] = (code *)0x0;
100: param_1[0x23] = (code *)0x0;
101: param_1[0x24] = (code *)0x0;
102: param_1[0x32] = (code *)0x0;
103: FUN_0012bb00(param_1);
104: FUN_00128bd0(param_1);
105: FUN_0011c750(param_1);
106: *(undefined4 *)((long)param_1 + 0x24) = 200;
107: puVar3 = (undefined8 *)(**(code **)param_1[1])(param_1,0,0x88);
108: bVar11 = ((ulong)puVar3 & 1) != 0;
109: param_1[0x44] = (code *)puVar3;
110: uVar7 = 0x88;
111: iVar5 = 0x88;
112: if (bVar11) {
113: *(undefined *)puVar3 = 0;
114: uVar7 = 0x87;
115: iVar5 = 0x87;
116: puVar3 = (undefined8 *)((long)puVar3 + 1);
117: }
118: if (((ulong)puVar3 & 2) == 0) {
119: uVar6 = (uint)uVar7;
120: }
121: else {
122: uVar6 = iVar5 - 2;
123: uVar7 = (ulong)uVar6;
124: *(undefined2 *)puVar3 = 0;
125: puVar3 = (undefined8 *)((long)puVar3 + 2);
126: }
127: if (((ulong)puVar3 & 4) != 0) {
128: *(undefined4 *)puVar3 = 0;
129: uVar7 = (ulong)(uVar6 - 4);
130: puVar3 = (undefined8 *)((long)puVar3 + 4);
131: }
132: uVar4 = uVar7 >> 3;
133: while (uVar4 != 0) {
134: uVar4 = uVar4 - 1;
135: *puVar3 = 0;
136: puVar3 = puVar3 + (ulong)bVar12 * -2 + 1;
137: }
138: if ((uVar7 & 4) != 0) {
139: *(undefined4 *)puVar3 = 0;
140: puVar3 = (undefined8 *)((long)puVar3 + 4);
141: }
142: puVar10 = puVar3;
143: if ((uVar7 & 2) != 0) {
144: puVar10 = (undefined8 *)((long)puVar3 + 2);
145: *(undefined2 *)puVar3 = 0;
146: }
147: if (bVar11) {
148: *(undefined *)puVar10 = 0;
149: }
150: return;
151: }
152: 
