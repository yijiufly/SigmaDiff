1: 
2: void FUN_00138dc0(long param_1,long param_2,long param_3,long *param_4,uint param_5)
3: 
4: {
5: undefined uVar1;
6: long lVar2;
7: short *psVar3;
8: int iVar4;
9: long lVar5;
10: int iVar6;
11: uint uVar7;
12: undefined *puVar8;
13: int *piVar9;
14: int iVar10;
15: long lVar11;
16: int iVar12;
17: int aiStack104 [5];
18: int iStack84;
19: int iStack76;
20: int aiStack72 [5];
21: int iStack52;
22: int iStack44;
23: 
24: param_3 = param_3 + 2;
25: iVar10 = 7;
26: uVar7 = 8;
27: lVar2 = *(long *)(param_1 + 0x1a8);
28: piVar9 = aiStack104;
29: psVar3 = *(short **)(param_2 + 0x58);
30: do {
31: if ((uVar7 & 0xfffffffd) == 4) {
32: LAB_00138e8e:
33: if (iVar10 == 0) {
34: puVar8 = (undefined *)((ulong)param_5 + *param_4);
35: if ((((aiStack104[1] == 0) && (aiStack104[3] == 0)) && (iStack84 == 0)) && (iStack76 == 0))
36: {
37: uVar1 = *(undefined *)
38: (lVar2 + 0x80 + (ulong)((uint)((long)aiStack104[0] + 0x10 >> 5) & 0x3ff));
39: *puVar8 = uVar1;
40: puVar8[1] = uVar1;
41: }
42: else {
43: lVar5 = (long)iStack76 * -0x1712 + (long)iStack84 * 0x1b37 + (long)aiStack104[3] * -0x28ba
44: + (long)aiStack104[1] * 0x73fc;
45: *puVar8 = *(undefined *)
46: (lVar2 + 0x80 +
47: (ulong)((uint)(lVar5 + 0x80000 + (long)aiStack104[0] * 0x8000 >> 0x14) & 0x3ff)
48: );
49: puVar8[1] = *(undefined *)
50: (lVar2 + 0x80 +
51: (ulong)((uint)(((long)aiStack104[0] * 0x8000 - lVar5) + 0x80000 >> 0x14) &
52: 0x3ff));
53: }
54: puVar8 = (undefined *)((ulong)param_5 + param_4[1]);
55: if (aiStack72[1] == 0) {
56: lVar5 = (long)aiStack72[3];
57: if ((aiStack72[3] == 0) && (iStack52 == 0)) {
58: if (iStack44 == 0) {
59: uVar1 = *(undefined *)
60: (lVar2 + 0x80 + (ulong)((uint)((long)aiStack72[0] + 0x10 >> 5) & 0x3ff));
61: *puVar8 = uVar1;
62: puVar8[1] = uVar1;
63: return;
64: }
65: lVar5 = 0;
66: }
67: }
68: else {
69: lVar5 = (long)aiStack72[3];
70: }
71: lVar5 = (long)iStack44 * -0x1712 + (long)iStack52 * 0x1b37 + lVar5 * -0x28ba +
72: (long)aiStack72[1] * 0x73fc;
73: *puVar8 = *(undefined *)
74: (lVar2 + 0x80 +
75: (ulong)((uint)((long)aiStack72[0] * 0x8000 + 0x80000 + lVar5 >> 0x14) & 0x3ff));
76: puVar8[1] = *(undefined *)
77: (lVar2 + 0x80 +
78: (ulong)((uint)(((long)aiStack72[0] * 0x8000 - lVar5) + 0x80000 >> 0x14) & 0x3ff
79: ));
80: return;
81: }
82: }
83: else {
84: if (uVar7 != 2) {
85: if (*(short *)(param_3 + 0xe) == 0) {
86: iVar4 = (int)*(short *)(param_3 + 0x2e);
87: if (*(short *)(param_3 + 0x2e) == 0) {
88: iVar6 = (int)*(short *)(param_3 + 0x4e);
89: iVar4 = 0;
90: iVar12 = (int)*(short *)(param_3 + 0x6e);
91: if (*(short *)(param_3 + 0x4e) == 0) {
92: if (*(short *)(param_3 + 0x6e) == 0) {
93: iVar4 = (int)((long)((int)*(short *)(param_3 + -2) * (int)*psVar3) << 2);
94: *piVar9 = iVar4;
95: piVar9[8] = iVar4;
96: goto LAB_00138e8e;
97: }
98: iVar4 = 0;
99: iVar6 = 0;
100: }
101: }
102: else {
103: iVar12 = (int)*(short *)(param_3 + 0x6e);
104: iVar6 = (int)*(short *)(param_3 + 0x4e);
105: }
106: }
107: else {
108: iVar12 = (int)*(short *)(param_3 + 0x6e);
109: iVar6 = (int)*(short *)(param_3 + 0x4e);
110: iVar4 = (int)*(short *)(param_3 + 0x2e);
111: }
112: lVar11 = (long)((int)*(short *)(param_3 + -2) * (int)*psVar3) * 0x8000;
113: lVar5 = (long)((int)*(short *)(param_3 + 0xe) * (int)psVar3[8]) * 0x73fc +
114: (long)(iVar4 * psVar3[0x18]) * -0x28ba +
115: (long)(iVar12 * psVar3[0x38]) * -0x1712 + (long)(iVar6 * psVar3[0x28]) * 0x1b37;
116: *piVar9 = (int)(lVar11 + 0x1000 + lVar5 >> 0xd);
117: piVar9[8] = (int)((lVar11 - lVar5) + 0x1000 >> 0xd);
118: goto LAB_00138e8e;
119: }
120: }
121: piVar9 = piVar9 + 1;
122: uVar7 = uVar7 - 1;
123: param_3 = param_3 + 2;
124: iVar10 = iVar10 + -1;
125: psVar3 = psVar3 + 1;
126: } while( true );
127: }
128: 
