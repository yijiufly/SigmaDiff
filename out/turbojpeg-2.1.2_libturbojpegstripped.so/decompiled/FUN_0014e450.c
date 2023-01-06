1: 
2: void FUN_0014e450(long param_1,int param_2,int param_3,int param_4,uint param_5)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: byte *pbVar3;
8: char *pcVar4;
9: __int32_t **pp_Var5;
10: int iVar6;
11: long lVar7;
12: int iVar8;
13: byte *pbVar9;
14: long in_FS_OFFSET;
15: bool bVar10;
16: bool bVar11;
17: byte bVar12;
18: uint uStack68;
19: long lStack64;
20: 
21: bVar12 = 0;
22: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
23: *(undefined4 *)(param_1 + 0x3c) = *(undefined4 *)(&DAT_0018fc80 + (long)param_2 * 4);
24: *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(&DAT_0018fd80 + (long)param_2 * 4);
25: FUN_0011fa80();
26: pbVar3 = (byte *)getenv("TJ_OPTIMIZE");
27: if (pbVar3 != (byte *)0x0) {
28: bVar10 = false;
29: bVar11 = *pbVar3 == 0;
30: if (!bVar11) {
31: lVar7 = 2;
32: pbVar9 = (byte *)0x18f67b;
33: do {
34: if (lVar7 == 0) break;
35: lVar7 = lVar7 + -1;
36: bVar10 = *pbVar3 < *pbVar9;
37: bVar11 = *pbVar3 == *pbVar9;
38: pbVar3 = pbVar3 + (ulong)bVar12 * -2 + 1;
39: pbVar9 = pbVar9 + (ulong)bVar12 * -2 + 1;
40: } while (bVar11);
41: if ((!bVar10 && !bVar11) == bVar10) {
42: *(undefined4 *)(param_1 + 0x108) = 1;
43: }
44: }
45: }
46: pbVar3 = (byte *)getenv("TJ_ARITHMETIC");
47: if (pbVar3 != (byte *)0x0) {
48: bVar10 = false;
49: bVar11 = *pbVar3 == 0;
50: if (!bVar11) {
51: lVar7 = 2;
52: pbVar9 = (byte *)0x18f67b;
53: do {
54: if (lVar7 == 0) break;
55: lVar7 = lVar7 + -1;
56: bVar10 = *pbVar3 < *pbVar9;
57: bVar11 = *pbVar3 == *pbVar9;
58: pbVar3 = pbVar3 + (ulong)bVar12 * -2 + 1;
59: pbVar9 = pbVar9 + (ulong)bVar12 * -2 + 1;
60: } while (bVar11);
61: if ((!bVar10 && !bVar11) == bVar10) {
62: *(undefined4 *)(param_1 + 0x104) = 1;
63: }
64: }
65: }
66: pcVar4 = getenv("TJ_RESTART");
67: if ((pcVar4 != (char *)0x0) && (*pcVar4 != '\0')) {
68: uStack68 = 0xffffffff;
69: iVar2 = __isoc99_sscanf(pcVar4,&DAT_0018f635,&uStack68);
70: uVar1 = uStack68;
71: if ((0 < iVar2) && (uStack68 < 0x10000)) {
72: pp_Var5 = __ctype_toupper_loc();
73: if (**pp_Var5 == 0x42) {
74: *(uint *)(param_1 + 0x118) = uVar1;
75: *(undefined4 *)(param_1 + 0x11c) = 0;
76: }
77: else {
78: *(uint *)(param_1 + 0x11c) = uVar1;
79: }
80: }
81: }
82: if (param_4 < 0) {
83: LAB_0014e4f6:
84: if (param_3 != 3) goto LAB_0014e4ff;
85: LAB_0014e722:
86: FUN_0011f6f0(param_1);
87: }
88: else {
89: FUN_0011f6c0(param_1,param_4,1);
90: if ((param_4 < 0x60) && ((param_5 & 0x1000) == 0)) {
91: *(undefined4 *)(param_1 + 0x114) = 1;
92: goto LAB_0014e4f6;
93: }
94: *(undefined4 *)(param_1 + 0x114) = 0;
95: if (param_3 == 3) goto LAB_0014e722;
96: LAB_0014e4ff:
97: if (param_2 == 0xb) {
98: FUN_0011f6f0(param_1);
99: }
100: else {
101: FUN_0011f6f0(param_1);
102: }
103: }
104: if ((param_5 & 0x4000) == 0) {
105: pbVar3 = (byte *)getenv("TJ_PROGRESSIVE");
106: if (pbVar3 == (byte *)0x0) goto LAB_0014e540;
107: bVar10 = false;
108: bVar11 = *pbVar3 == 0;
109: if (bVar11) goto LAB_0014e540;
110: lVar7 = 2;
111: pbVar9 = (byte *)0x18f67b;
112: do {
113: if (lVar7 == 0) break;
114: lVar7 = lVar7 + -1;
115: bVar10 = *pbVar3 < *pbVar9;
116: bVar11 = *pbVar3 == *pbVar9;
117: pbVar3 = pbVar3 + (ulong)bVar12 * -2 + 1;
118: pbVar9 = pbVar9 + (ulong)bVar12 * -2 + 1;
119: } while (bVar11);
120: if ((!bVar10 && !bVar11) != bVar10) goto LAB_0014e540;
121: }
122: FUN_0011ffa0(param_1);
123: LAB_0014e540:
124: lVar7 = *(long *)(param_1 + 0x58);
125: iVar2 = *(int *)(&DAT_0018fdd0 + (long)param_3 * 4);
126: *(undefined4 *)(lVar7 + 0x68) = 1;
127: *(undefined4 *)(lVar7 + 200) = 1;
128: iVar6 = iVar2 + 7;
129: if (-1 < iVar2) {
130: iVar6 = iVar2;
131: }
132: iVar2 = *(int *)(&DAT_0018fdb0 + (long)param_3 * 4);
133: *(int *)(lVar7 + 8) = iVar6 >> 3;
134: iVar8 = iVar2 + 7;
135: if (-1 < iVar2) {
136: iVar8 = iVar2;
137: }
138: iVar8 = iVar8 >> 3;
139: if (*(int *)(param_1 + 0x4c) < 4) {
140: *(int *)(lVar7 + 0xc) = iVar8;
141: *(undefined4 *)(lVar7 + 0x6c) = 1;
142: *(undefined4 *)(lVar7 + 0xcc) = 1;
143: }
144: else {
145: *(int *)(lVar7 + 0x128) = iVar6 >> 3;
146: *(int *)(lVar7 + 0xc) = iVar8;
147: *(undefined4 *)(lVar7 + 0x6c) = 1;
148: *(undefined4 *)(lVar7 + 0xcc) = 1;
149: *(int *)(lVar7 + 300) = iVar8;
150: }
151: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
152: return;
153: }
154: /* WARNING: Subroutine does not return */
155: __stack_chk_fail();
156: }
157: 
