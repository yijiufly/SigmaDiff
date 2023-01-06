1: 
2: undefined8 FUN_0013fa10(long param_1,long *param_2)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: uint uVar5;
10: uint uVar6;
11: byte bVar7;
12: int iVar8;
13: int iVar9;
14: int iVar10;
15: long lVar11;
16: long lVar12;
17: int iStack108;
18: 
19: lVar3 = *(long *)(param_1 + 0x1f0);
20: if (*(int *)(param_1 + 0x118) != 0) {
21: iVar10 = *(int *)(lVar3 + 0x60);
22: if (iVar10 == 0) {
23: FUN_0013ef30(param_1,*(undefined4 *)(lVar3 + 100));
24: iVar10 = *(int *)(param_1 + 0x118);
25: *(uint *)(lVar3 + 100) = *(int *)(lVar3 + 100) + 1U & 7;
26: }
27: *(int *)(lVar3 + 0x60) = iVar10 + -1;
28: }
29: iVar10 = *(int *)(param_1 + 0x1a0);
30: lVar4 = *param_2;
31: iVar2 = *(int *)(*(long *)(param_1 + 0x148) + 0x18);
32: iStack108 = iVar10;
33: if (0 < iVar10) {
34: do {
35: iVar9 = (int)*(short *)(lVar4 + (long)*(int *)(&DAT_0018b460 + (long)iStack108 * 4) * 2);
36: bVar7 = (byte)*(undefined4 *)(param_1 + 0x1a8);
37: if (iVar9 < 0) {
38: iVar9 = -iVar9 >> (bVar7 & 0x1f);
39: }
40: else {
41: iVar9 = iVar9 >> (bVar7 & 0x1f);
42: }
43: } while ((iVar9 == 0) && (iStack108 = iStack108 + -1, iStack108 != 0));
44: }
45: iVar9 = *(int *)(param_1 + 0x19c);
46: if (iVar9 <= iStack108) {
47: lVar1 = lVar3 + (long)iVar2 * 8;
48: LAB_0013fae8:
49: lVar11 = (long)(iVar9 * 3 + -3) + *(long *)(lVar1 + 0xe8);
50: FUN_0013e1a0(param_1,lVar11);
51: do {
52: iVar10 = (int)*(short *)(lVar4 + (long)*(int *)(&DAT_0018b460 + (long)iVar9 * 4) * 2);
53: if (iVar10 < 0) {
54: iVar10 = -iVar10 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
55: if (iVar10 != 0) goto code_r0x0013fb58;
56: }
57: else {
58: iVar10 = iVar10 >> ((byte)*(undefined4 *)(param_1 + 0x1a8) & 0x1f);
59: if (iVar10 != 0) {
60: FUN_0013dd70(param_1,lVar11 + 1);
61: FUN_0013e1a0(param_1,lVar3 + 0x168);
62: goto joined_r0x0013fc01;
63: }
64: }
65: lVar12 = lVar11 + 1;
66: lVar11 = lVar11 + 3;
67: iVar9 = iVar9 + 1;
68: FUN_0013e1a0(param_1,lVar12);
69: } while( true );
70: }
71: LAB_0013fb9d:
72: if (iVar9 <= iVar10) {
73: FUN_0013dd70(param_1,(long)(iVar9 * 3 + -3) + *(long *)(lVar3 + 0xe8 + (long)iVar2 * 8));
74: }
75: return 1;
76: code_r0x0013fb58:
77: FUN_0013dd70(param_1,lVar11 + 1);
78: FUN_0013dd70(param_1,lVar3 + 0x168);
79: joined_r0x0013fc01:
80: uVar5 = iVar10 - 1;
81: if (uVar5 != 0) {
82: FUN_0013dd70(param_1,lVar11 + 2);
83: if (uVar5 >> 1 != 0) {
84: lVar12 = 0xbd;
85: FUN_0013dd70(param_1,lVar11 + 2);
86: if ((int)(uint)*(byte *)(param_1 + 0xe0 + (long)iVar2) < iVar9) {
87: lVar12 = 0xd9;
88: }
89: lVar12 = lVar12 + *(long *)(lVar1 + 0xe8);
90: iVar10 = (int)uVar5 >> 2;
91: if (iVar10 == 0) {
92: FUN_0013e1a0(param_1,lVar12);
93: lVar11 = lVar12 + 0xe;
94: uVar6 = 1;
95: }
96: else {
97: iVar8 = 2;
98: do {
99: lVar11 = lVar12;
100: iVar8 = iVar8 * 2;
101: FUN_0013dd70(param_1,lVar11);
102: iVar10 = iVar10 >> 1;
103: lVar12 = lVar11 + 1;
104: } while (iVar10 != 0);
105: FUN_0013e1a0(param_1,lVar11 + 1);
106: lVar11 = lVar11 + 0xf;
107: uVar6 = iVar8 >> 1;
108: if (uVar6 == 0) goto LAB_0013fb8a;
109: }
110: do {
111: FUN_0013e5d0(param_1,lVar11,(uVar6 & uVar5) != 0);
112: uVar6 = (int)uVar6 >> 1;
113: } while (uVar6 != 0);
114: goto LAB_0013fb8a;
115: }
116: }
117: FUN_0013e1a0(param_1,lVar11 + 2);
118: LAB_0013fb8a:
119: iVar9 = iVar9 + 1;
120: if (iStack108 < iVar9) goto code_r0x0013fb97;
121: goto LAB_0013fae8;
122: code_r0x0013fb97:
123: iVar10 = *(int *)(param_1 + 0x1a0);
124: goto LAB_0013fb9d;
125: }
126: 
