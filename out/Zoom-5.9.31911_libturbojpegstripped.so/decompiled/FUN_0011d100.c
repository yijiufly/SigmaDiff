1: 
2: ulong FUN_0011d100(code **param_1)
3: 
4: {
5: undefined4 uVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: code *pcVar5;
10: int *piVar6;
11: ulong uVar7;
12: 
13: uVar1 = *(undefined4 *)((long)param_1 + 0x24);
14: switch(uVar1) {
15: case 200:
16: break;
17: case 0xc9:
18: goto code_r0x0011d14b;
19: case 0xca:
20: return 1;
21: case 0xcb:
22: case 0xcc:
23: case 0xcd:
24: case 0xce:
25: case 0xcf:
26: case 0xd0:
27: case 0xd2:
28: /* WARNING: Could not recover jumptable at 0x0011d187. Too many branches */
29: /* WARNING: Treating indirect jump as call */
30: uVar7 = (**(code **)param_1[0x48])();
31: return uVar7;
32: default:
33: pcVar5 = *param_1;
34: *(undefined4 *)(pcVar5 + 0x28) = 0x14;
35: *(undefined4 *)(pcVar5 + 0x2c) = uVar1;
36: (**(code **)*param_1)(param_1);
37: return 0;
38: }
39: (**(code **)(param_1[0x48] + 8))();
40: (**(code **)(param_1[5] + 0x10))(param_1);
41: *(undefined4 *)((long)param_1 + 0x24) = 0xc9;
42: code_r0x0011d14b:
43: uVar7 = (**(code **)param_1[0x48])();
44: if ((int)uVar7 != 1) {
45: return uVar7;
46: }
47: iVar2 = *(int *)(param_1 + 7);
48: if (iVar2 != 3) {
49: if (iVar2 == 4) {
50: if ((*(int *)(param_1 + 0x30) == 0) || (*(char *)((long)param_1 + 0x184) == '\0')) {
51: *(undefined4 *)((long)param_1 + 0x3c) = 4;
52: }
53: else {
54: if (*(char *)((long)param_1 + 0x184) == '\x02') {
55: *(undefined4 *)((long)param_1 + 0x3c) = 5;
56: }
57: else {
58: pcVar5 = *param_1;
59: *(undefined4 *)(pcVar5 + 0x28) = 0x72;
60: *(uint *)(pcVar5 + 0x2c) = (uint)*(byte *)((long)param_1 + 0x184);
61: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
62: *(undefined4 *)((long)param_1 + 0x3c) = 5;
63: uVar7 = uVar7 & 0xffffffff;
64: }
65: }
66: *(undefined4 *)(param_1 + 8) = 4;
67: }
68: else {
69: if (iVar2 == 1) {
70: *(undefined4 *)((long)param_1 + 0x3c) = 1;
71: *(undefined4 *)(param_1 + 8) = 1;
72: }
73: else {
74: *(undefined4 *)((long)param_1 + 0x3c) = 0;
75: *(undefined4 *)(param_1 + 8) = 0;
76: }
77: }
78: goto code_r0x0011d1dc;
79: }
80: if (*(int *)((long)param_1 + 0x174) == 0) {
81: if (*(int *)(param_1 + 0x30) == 0) {
82: piVar6 = (int *)param_1[0x26];
83: iVar2 = *piVar6;
84: iVar3 = piVar6[0x18];
85: iVar4 = piVar6[0x30];
86: if (((iVar2 != 1) || (iVar3 != 2)) || (iVar4 != 3)) {
87: if (((iVar2 != 0x52) || (iVar3 != 0x47)) || (iVar4 != 0x42)) {
88: pcVar5 = *param_1;
89: *(int *)(pcVar5 + 0x30) = iVar3;
90: *(int *)(pcVar5 + 0x34) = iVar4;
91: *(int *)(pcVar5 + 0x2c) = iVar2;
92: *(undefined4 *)(pcVar5 + 0x28) = 0x6f;
93: (**(code **)(pcVar5 + 8))(param_1,1);
94: *(undefined4 *)((long)param_1 + 0x3c) = 3;
95: uVar7 = uVar7 & 0xffffffff;
96: goto code_r0x0011d2d8;
97: }
98: goto code_r0x0011d3df;
99: }
100: goto code_r0x0011d33d;
101: }
102: if (*(char *)((long)param_1 + 0x184) == '\0') {
103: code_r0x0011d3df:
104: *(undefined4 *)((long)param_1 + 0x3c) = 2;
105: }
106: else {
107: if (*(char *)((long)param_1 + 0x184) == '\x01') goto code_r0x0011d33d;
108: pcVar5 = *param_1;
109: *(undefined4 *)(pcVar5 + 0x28) = 0x72;
110: *(uint *)(pcVar5 + 0x2c) = (uint)*(byte *)((long)param_1 + 0x184);
111: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
112: uVar7 = uVar7 & 0xffffffff;
113: *(undefined4 *)((long)param_1 + 0x3c) = 3;
114: }
115: }
116: else {
117: code_r0x0011d33d:
118: *(undefined4 *)((long)param_1 + 0x3c) = 3;
119: }
120: code_r0x0011d2d8:
121: *(undefined4 *)(param_1 + 8) = 2;
122: code_r0x0011d1dc:
123: *(undefined4 *)((long)param_1 + 0x44) = 1;
124: *(undefined4 *)(param_1 + 9) = 1;
125: *(undefined4 *)(param_1 + 0xb) = 0;
126: param_1[10] = (code *)0x3ff0000000000000;
127: *(undefined4 *)((long)param_1 + 0x5c) = 0;
128: *(undefined4 *)(param_1 + 0xc) = 0;
129: *(undefined4 *)((long)param_1 + 100) = 1;
130: *(undefined4 *)(param_1 + 0xd) = 1;
131: *(undefined4 *)((long)param_1 + 0x6c) = 0;
132: *(undefined4 *)(param_1 + 0xe) = 2;
133: *(undefined4 *)((long)param_1 + 0x74) = 1;
134: *(undefined4 *)(param_1 + 0xf) = 0x100;
135: param_1[0x14] = (code *)0x0;
136: *(undefined4 *)((long)param_1 + 0x7c) = 0;
137: *(undefined4 *)(param_1 + 0x10) = 0;
138: *(undefined4 *)((long)param_1 + 0x84) = 0;
139: *(undefined4 *)((long)param_1 + 0x24) = 0xca;
140: return uVar7;
141: }
142: 
