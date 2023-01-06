1: 
2: void FUN_00106730(code **param_1)
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
13: *ppcVar4 = FUN_00106720;
14: switch((ulong)*(uint *)((long)param_1 + 0x3c)) {
15: default:
16: if (*(int *)(param_1 + 7) < 1) {
17: LAB_00106786:
18: ppcVar2 = (code **)*param_1;
19: *(undefined4 *)(ppcVar2 + 5) = 9;
20: (**ppcVar2)(param_1);
21: }
22: break;
23: case 1:
24: if (*(int *)(param_1 + 7) != 1) {
25: ppcVar2 = (code **)*param_1;
26: *(undefined4 *)(ppcVar2 + 5) = 9;
27: (**ppcVar2)(param_1);
28: }
29: break;
30: case 2:
31: case 6:
32: case 7:
33: case 8:
34: case 9:
35: case 10:
36: case 0xb:
37: case 0xc:
38: case 0xd:
39: case 0xe:
40: case 0xf:
41: if (*(int *)(param_1 + 7) !=
42: *(int *)(&UNK_00168bc0 + (ulong)*(uint *)((long)param_1 + 0x3c) * 4)) {
43: ppcVar2 = (code **)*param_1;
44: *(undefined4 *)(ppcVar2 + 5) = 9;
45: (**ppcVar2)(param_1);
46: }
47: break;
48: case 3:
49: if (*(int *)(param_1 + 7) != 3) {
50: ppcVar2 = (code **)*param_1;
51: *(undefined4 *)(ppcVar2 + 5) = 9;
52: (**ppcVar2)(param_1);
53: }
54: break;
55: case 4:
56: case 5:
57: if (*(int *)(param_1 + 7) != 4) goto LAB_00106786;
58: }
59: switch(*(int *)(param_1 + 10)) {
60: default:
61: if ((*(int *)(param_1 + 10) != *(int *)((long)param_1 + 0x3c)) ||
62: (*(int *)((long)param_1 + 0x4c) != *(int *)(param_1 + 7))) {
63: ppcVar2 = (code **)*param_1;
64: *(undefined4 *)(ppcVar2 + 5) = 0x1b;
65: (**ppcVar2)(param_1);
66: }
67: break;
68: case 1:
69: if (*(int *)((long)param_1 + 0x4c) != 1) {
70: ppcVar2 = (code **)*param_1;
71: *(undefined4 *)(ppcVar2 + 5) = 10;
72: (**ppcVar2)(param_1);
73: }
74: iVar3 = *(int *)((long)param_1 + 0x3c);
75: if (iVar3 != 1) {
76: if ((iVar3 - 6U < 10) || (iVar3 == 2)) {
77: iVar3 = FUN_00167c90();
78: if (iVar3 != 0) {
79: ppcVar4[1] = FUN_00167e30;
80: return;
81: }
82: *ppcVar4 = FUN_001045b0;
83: ppcVar4[1] = FUN_00105040;
84: return;
85: }
86: if (iVar3 != 3) goto code_r0x0010685e;
87: }
88: ppcVar4[1] = FUN_00106270;
89: return;
90: case 2:
91: if (*(int *)((long)param_1 + 0x4c) != 3) {
92: ppcVar2 = (code **)*param_1;
93: *(undefined4 *)(ppcVar2 + 5) = 10;
94: (**ppcVar2)(param_1);
95: }
96: uVar1 = *(uint *)((long)param_1 + 0x3c);
97: uVar5 = (ulong)uVar1;
98: if ((((*(int *)(&UNK_00168ce0 + uVar5 * 4) != 0) || (*(int *)(&UNK_00168c80 + uVar5 * 4) != 1))
99: || (*(int *)(&UNK_00168c20 + uVar5 * 4) != 2)) || (*(int *)(&UNK_00168bc0 + uVar5 * 4) != 3)
100: ) {
101: if ((uVar1 - 6 < 10) || (uVar1 == 2)) {
102: ppcVar4[1] = FUN_00105370;
103: return;
104: }
105: code_r0x0010685e:
106: ppcVar4 = (code **)*param_1;
107: *(undefined4 *)(ppcVar4 + 5) = 0x1b;
108: /* WARNING: Could not recover jumptable at 0x00106874. Too many branches */
109: /* WARNING: Treating indirect jump as call */
110: (**ppcVar4)(param_1);
111: return;
112: }
113: break;
114: case 3:
115: if (*(int *)((long)param_1 + 0x4c) != 3) {
116: ppcVar2 = (code **)*param_1;
117: *(undefined4 *)(ppcVar2 + 5) = 10;
118: (**ppcVar2)(param_1);
119: }
120: iVar3 = *(int *)((long)param_1 + 0x3c);
121: if ((iVar3 - 6U < 10) || (iVar3 == 2)) {
122: iVar3 = FUN_00167c30();
123: if (iVar3 != 0) {
124: ppcVar4[1] = FUN_00167d60;
125: return;
126: }
127: *ppcVar4 = FUN_001045b0;
128: ppcVar4[1] = FUN_001049a0;
129: return;
130: }
131: if (iVar3 != 3) goto code_r0x0010685e;
132: break;
133: case 4:
134: if (*(int *)((long)param_1 + 0x4c) != 4) {
135: ppcVar2 = (code **)*param_1;
136: *(undefined4 *)(ppcVar2 + 5) = 10;
137: (**ppcVar2)(param_1);
138: }
139: if (*(int *)((long)param_1 + 0x3c) != 4) goto code_r0x0010685e;
140: break;
141: case 5:
142: if (*(int *)((long)param_1 + 0x4c) != 4) {
143: ppcVar2 = (code **)*param_1;
144: *(undefined4 *)(ppcVar2 + 5) = 10;
145: (**ppcVar2)(param_1);
146: }
147: if (*(int *)((long)param_1 + 0x3c) == 4) {
148: *ppcVar4 = FUN_001045b0;
149: ppcVar4[1] = FUN_00106110;
150: return;
151: }
152: if (*(int *)((long)param_1 + 0x3c) != 5) goto code_r0x0010685e;
153: }
154: ppcVar4[1] = FUN_001062c0;
155: return;
156: }
157: 
