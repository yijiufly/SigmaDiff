1: 
2: ulong FUN_00125060(code **param_1)
3: 
4: {
5: byte bVar1;
6: undefined4 uVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: code **ppcVar6;
11: int *piVar7;
12: code *pcVar8;
13: ulong uVar9;
14: 
15: uVar2 = *(undefined4 *)((long)param_1 + 0x24);
16: switch(uVar2) {
17: case 200:
18: break;
19: case 0xc9:
20: goto code_r0x001250ab;
21: case 0xca:
22: return 1;
23: case 0xcb:
24: case 0xcc:
25: case 0xcd:
26: case 0xce:
27: case 0xcf:
28: case 0xd0:
29: case 0xd2:
30: /* WARNING: Could not recover jumptable at 0x001250e7. Too many branches */
31: /* WARNING: Treating indirect jump as call */
32: uVar9 = (**(code **)param_1[0x48])();
33: return uVar9;
34: default:
35: ppcVar6 = (code **)*param_1;
36: *(undefined4 *)(ppcVar6 + 5) = 0x14;
37: *(undefined4 *)((long)ppcVar6 + 0x2c) = uVar2;
38: (**ppcVar6)(param_1);
39: return 0;
40: }
41: (**(code **)(param_1[0x48] + 8))();
42: (**(code **)(param_1[5] + 0x10))(param_1);
43: *(undefined4 *)((long)param_1 + 0x24) = 0xc9;
44: code_r0x001250ab:
45: uVar9 = (**(code **)param_1[0x48])();
46: if ((int)uVar9 != 1) {
47: return uVar9;
48: }
49: iVar3 = *(int *)(param_1 + 7);
50: if (iVar3 != 3) {
51: if (iVar3 == 4) {
52: if ((*(int *)(param_1 + 0x30) == 0) || (bVar1 = *(byte *)((long)param_1 + 0x184), bVar1 == 0))
53: {
54: *(undefined4 *)((long)param_1 + 0x3c) = 4;
55: }
56: else {
57: if (bVar1 == 2) {
58: *(undefined4 *)((long)param_1 + 0x3c) = 5;
59: }
60: else {
61: pcVar8 = *param_1;
62: *(undefined4 *)(pcVar8 + 0x28) = 0x72;
63: *(uint *)(pcVar8 + 0x2c) = (uint)bVar1;
64: (**(code **)(pcVar8 + 8))(param_1,0xffffffff);
65: *(undefined4 *)((long)param_1 + 0x3c) = 5;
66: uVar9 = uVar9 & 0xffffffff;
67: }
68: }
69: *(undefined4 *)(param_1 + 8) = 4;
70: }
71: else {
72: if (iVar3 == 1) {
73: *(undefined4 *)((long)param_1 + 0x3c) = 1;
74: *(undefined4 *)(param_1 + 8) = 1;
75: }
76: else {
77: *(undefined4 *)((long)param_1 + 0x3c) = 0;
78: *(undefined4 *)(param_1 + 8) = 0;
79: }
80: }
81: goto code_r0x0012513c;
82: }
83: if (*(int *)((long)param_1 + 0x174) == 0) {
84: if (*(int *)(param_1 + 0x30) == 0) {
85: piVar7 = (int *)param_1[0x26];
86: iVar3 = *piVar7;
87: iVar4 = piVar7[0x18];
88: iVar5 = piVar7[0x30];
89: if ((iVar3 == 1) && (iVar4 == 2)) {
90: if (iVar5 == 3) goto code_r0x00125278;
91: }
92: else {
93: if ((iVar3 == 0x52 && iVar4 == 0x47) && (iVar5 == 0x42)) goto code_r0x00125317;
94: }
95: pcVar8 = *param_1;
96: *(int *)(pcVar8 + 0x30) = iVar4;
97: *(int *)(pcVar8 + 0x34) = iVar5;
98: *(int *)(pcVar8 + 0x2c) = iVar3;
99: *(undefined4 *)(pcVar8 + 0x28) = 0x6f;
100: (**(code **)(pcVar8 + 8))(param_1,1);
101: *(undefined4 *)((long)param_1 + 0x3c) = 3;
102: uVar9 = uVar9 & 0xffffffff;
103: }
104: else {
105: bVar1 = *(byte *)((long)param_1 + 0x184);
106: if (bVar1 == 0) {
107: code_r0x00125317:
108: *(undefined4 *)((long)param_1 + 0x3c) = 2;
109: }
110: else {
111: if (bVar1 == 1) goto code_r0x00125278;
112: pcVar8 = *param_1;
113: *(undefined4 *)(pcVar8 + 0x28) = 0x72;
114: *(uint *)(pcVar8 + 0x2c) = (uint)bVar1;
115: (**(code **)(pcVar8 + 8))(param_1,0xffffffff);
116: uVar9 = uVar9 & 0xffffffff;
117: *(undefined4 *)((long)param_1 + 0x3c) = 3;
118: }
119: }
120: }
121: else {
122: code_r0x00125278:
123: *(undefined4 *)((long)param_1 + 0x3c) = 3;
124: }
125: *(undefined4 *)(param_1 + 8) = 2;
126: code_r0x0012513c:
127: *(undefined8 *)((long)param_1 + 0x44) = 0x100000001;
128: param_1[10] = (code *)0x3ff0000000000000;
129: param_1[0xb] = (code *)0x0;
130: *(undefined4 *)(param_1 + 0xc) = 0;
131: *(undefined8 *)((long)param_1 + 100) = 0x100000001;
132: *(undefined4 *)((long)param_1 + 0x6c) = 0;
133: *(undefined4 *)(param_1 + 0xe) = 2;
134: param_1[0x14] = (code *)0x0;
135: *(undefined4 *)((long)param_1 + 0x74) = 1;
136: *(undefined4 *)(param_1 + 0xf) = 0x100;
137: *(undefined4 *)((long)param_1 + 0x7c) = 0;
138: *(undefined4 *)(param_1 + 0x10) = 0;
139: *(undefined4 *)((long)param_1 + 0x84) = 0;
140: *(undefined4 *)((long)param_1 + 0x24) = 0xca;
141: return uVar9;
142: }
143: 
