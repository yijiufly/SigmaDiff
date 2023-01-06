1: 
2: void FUN_00106ef0(code **param_1)
3: 
4: {
5: uint uVar1;
6: code **ppcVar2;
7: int iVar3;
8: code **ppcVar4;
9: ulong uVar5;
10: 
11: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x18);
12: param_1[0x3b] = (code *)ppcVar4;
13: *ppcVar4 = FUN_00106ee0;
14: switch((ulong)*(uint *)((long)param_1 + 0x3c)) {
15: default:
16: if (*(int *)(param_1 + 7) < 1) {
17: LAB_00106f46:
18: ppcVar2 = (code **)*param_1;
19: *(undefined4 *)(ppcVar2 + 5) = 9;
20: (**ppcVar2)(param_1);
21: }
22: break;
23: case 1:
24: if (*(int *)(param_1 + 7) != 1) goto LAB_00106f46;
25: break;
26: case 2:
27: case 6:
28: case 7:
29: case 8:
30: case 9:
31: case 10:
32: case 0xb:
33: case 0xc:
34: case 0xd:
35: case 0xe:
36: case 0xf:
37: if (*(int *)(param_1 + 7) !=
38: *(int *)(&UNK_0016c400 + (ulong)*(uint *)((long)param_1 + 0x3c) * 4)) goto LAB_00106f46;
39: break;
40: case 3:
41: if (*(int *)(param_1 + 7) != 3) goto LAB_00106f46;
42: break;
43: case 4:
44: case 5:
45: if (*(int *)(param_1 + 7) != 4) goto LAB_00106f46;
46: }
47: switch(*(int *)(param_1 + 10)) {
48: default:
49: if ((*(int *)(param_1 + 10) != *(int *)((long)param_1 + 0x3c)) ||
50: (*(int *)((long)param_1 + 0x4c) != *(int *)(param_1 + 7))) {
51: ppcVar2 = (code **)*param_1;
52: *(undefined4 *)(ppcVar2 + 5) = 0x1b;
53: (**ppcVar2)(param_1);
54: }
55: break;
56: case 1:
57: if (*(int *)((long)param_1 + 0x4c) != 1) {
58: ppcVar2 = (code **)*param_1;
59: *(undefined4 *)(ppcVar2 + 5) = 10;
60: (**ppcVar2)(param_1);
61: }
62: iVar3 = *(int *)((long)param_1 + 0x3c);
63: if (iVar3 != 1) {
64: if ((iVar3 - 6U < 10) || (iVar3 == 2)) {
65: iVar3 = FUN_0016bec0();
66: if (iVar3 != 0) {
67: ppcVar4[1] = FUN_0016bf10;
68: return;
69: }
70: *ppcVar4 = FUN_00104240;
71: ppcVar4[1] = FUN_00104d40;
72: return;
73: }
74: if (iVar3 != 3) goto code_r0x00106fda;
75: }
76: ppcVar4[1] = FUN_00106790;
77: return;
78: case 2:
79: if (*(int *)((long)param_1 + 0x4c) != 3) {
80: ppcVar2 = (code **)*param_1;
81: *(undefined4 *)(ppcVar2 + 5) = 10;
82: (**ppcVar2)(param_1);
83: }
84: uVar1 = *(uint *)((long)param_1 + 0x3c);
85: uVar5 = (ulong)uVar1;
86: if ((((*(int *)(&UNK_0016c520 + uVar5 * 4) != 0) || (*(int *)(&UNK_0016c4c0 + uVar5 * 4) != 1))
87: || (*(int *)(&UNK_0016c460 + uVar5 * 4) != 2)) || (*(int *)(&UNK_0016c400 + uVar5 * 4) != 3)
88: ) {
89: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
90: ppcVar4[1] = FUN_001050f0;
91: return;
92: }
93: code_r0x00106fda:
94: ppcVar4 = (code **)*param_1;
95: *(undefined4 *)(ppcVar4 + 5) = 0x1b;
96: /* WARNING: Could not recover jumptable at 0x00106ff0. Too many branches */
97: /* WARNING: Treating indirect jump as call */
98: (**ppcVar4)(param_1);
99: return;
100: }
101: break;
102: case 3:
103: if (*(int *)((long)param_1 + 0x4c) != 3) {
104: ppcVar2 = (code **)*param_1;
105: *(undefined4 *)(ppcVar2 + 5) = 10;
106: (**ppcVar2)(param_1);
107: }
108: iVar3 = *(int *)((long)param_1 + 0x3c);
109: if ((iVar3 - 6U < 10) || (iVar3 == 2)) {
110: iVar3 = FUN_0016beb0();
111: if (iVar3 != 0) {
112: ppcVar4[1] = FUN_0016bf00;
113: return;
114: }
115: *ppcVar4 = FUN_00104240;
116: ppcVar4[1] = FUN_00104600;
117: return;
118: }
119: if (iVar3 != 3) goto code_r0x00106fda;
120: break;
121: case 4:
122: if (*(int *)((long)param_1 + 0x4c) != 4) {
123: ppcVar2 = (code **)*param_1;
124: *(undefined4 *)(ppcVar2 + 5) = 10;
125: (**ppcVar2)(param_1);
126: }
127: if (*(int *)((long)param_1 + 0x3c) != 4) goto code_r0x00106fda;
128: break;
129: case 5:
130: if (*(int *)((long)param_1 + 0x4c) != 4) {
131: ppcVar2 = (code **)*param_1;
132: *(undefined4 *)(ppcVar2 + 5) = 10;
133: (**ppcVar2)(param_1);
134: }
135: if (*(int *)((long)param_1 + 0x3c) == 4) {
136: *ppcVar4 = FUN_00104240;
137: ppcVar4[1] = FUN_00106610;
138: return;
139: }
140: if (*(int *)((long)param_1 + 0x3c) != 5) goto code_r0x00106fda;
141: }
142: ppcVar4[1] = FUN_001067f0;
143: return;
144: }
145: 
