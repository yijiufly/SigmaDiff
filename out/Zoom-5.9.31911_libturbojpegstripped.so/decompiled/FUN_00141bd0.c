1: 
2: undefined8 FUN_00141bd0(long param_1,int param_2,int param_3,int param_4,uint param_5)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: uint uVar3;
8: int iVar4;
9: char *pcVar5;
10: __int32_t **pp_Var6;
11: long lVar7;
12: uint auStack72 [6];
13: 
14: lVar7 = (long)param_3;
15: *(undefined4 *)(param_1 + 0x3c) = *(undefined4 *)(&DAT_0018bb40 + (long)param_2 * 4);
16: *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(&DAT_0018bc40 + (long)param_2 * 4);
17: FUN_00116eb0();
18: pcVar5 = getenv("TJ_OPTIMIZE");
19: if (((pcVar5 != (char *)0x0) && (*pcVar5 == '1')) && (pcVar5[1] == '\0')) {
20: *(undefined4 *)(param_1 + 0x108) = 1;
21: }
22: pcVar5 = getenv("TJ_ARITHMETIC");
23: if (((pcVar5 != (char *)0x0) && (*pcVar5 == '1')) && (pcVar5[1] == '\0')) {
24: *(undefined4 *)(param_1 + 0x104) = 1;
25: }
26: pcVar5 = getenv("TJ_RESTART");
27: if ((pcVar5 != (char *)0x0) && (*pcVar5 != '\0')) {
28: auStack72[0] = 0xffffffff;
29: iVar4 = __isoc99_sscanf(pcVar5,&DAT_0018b995,auStack72);
30: uVar3 = auStack72[0];
31: if ((0 < iVar4) && (auStack72[0] < 0x10000)) {
32: pp_Var6 = __ctype_toupper_loc();
33: if (**pp_Var6 == 0x42) {
34: *(uint *)(param_1 + 0x118) = uVar3;
35: *(undefined4 *)(param_1 + 0x11c) = 0;
36: }
37: else {
38: *(uint *)(param_1 + 0x11c) = uVar3;
39: }
40: }
41: }
42: if (param_4 < 0) {
43: LAB_00141c8e:
44: if (param_3 != 3) goto LAB_00141c98;
45: LAB_00141dd8:
46: FUN_001169b0(param_1,1);
47: }
48: else {
49: FUN_00116980(param_1,param_4,1);
50: if ((0x5f < param_4) || ((param_5 & 0x1000) != 0)) {
51: *(undefined4 *)(param_1 + 0x114) = 0;
52: goto LAB_00141c8e;
53: }
54: *(undefined4 *)(param_1 + 0x114) = 1;
55: if (param_3 == 3) goto LAB_00141dd8;
56: LAB_00141c98:
57: if (param_2 == 0xb) {
58: FUN_001169b0(param_1,5);
59: }
60: else {
61: FUN_001169b0(param_1,3);
62: }
63: }
64: if ((param_5 & 0x4000) == 0) {
65: pcVar5 = getenv("TJ_PROGRESSIVE");
66: if (((pcVar5 == (char *)0x0) || (*pcVar5 != '1')) || (pcVar5[1] != '\0')) goto LAB_00141ce0;
67: }
68: FUN_00117620(param_1);
69: LAB_00141ce0:
70: lVar2 = *(long *)(param_1 + 0x58);
71: iVar4 = *(int *)(&DAT_0018bc90 + lVar7 * 4);
72: *(undefined4 *)(lVar2 + 0x68) = 1;
73: *(undefined4 *)(lVar2 + 200) = 1;
74: if (iVar4 < 0) {
75: iVar4 = iVar4 + 7;
76: }
77: iVar1 = *(int *)(param_1 + 0x4c);
78: *(int *)(lVar2 + 8) = iVar4 >> 3;
79: if (iVar1 < 4) {
80: *(undefined4 *)(lVar2 + 0x6c) = 1;
81: *(undefined4 *)(lVar2 + 0xcc) = 1;
82: iVar4 = *(int *)(&DAT_0018bc70 + lVar7 * 4);
83: if (iVar4 < 0) {
84: iVar4 = iVar4 + 7;
85: }
86: *(int *)(lVar2 + 0xc) = iVar4 >> 3;
87: }
88: else {
89: *(int *)(lVar2 + 0x128) = iVar4 >> 3;
90: *(undefined4 *)(lVar2 + 0x6c) = 1;
91: *(undefined4 *)(lVar2 + 0xcc) = 1;
92: iVar4 = *(int *)(&DAT_0018bc70 + lVar7 * 4);
93: if (iVar4 < 0) {
94: iVar4 = iVar4 + 7;
95: }
96: *(int *)(lVar2 + 0xc) = iVar4 >> 3;
97: *(int *)(lVar2 + 300) = iVar4 >> 3;
98: }
99: return 0;
100: }
101: 
