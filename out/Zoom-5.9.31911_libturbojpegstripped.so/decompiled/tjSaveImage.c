1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8
5: tjSaveImage(char *param_1,long param_2,int param_3,ulong param_4,int param_5,uint param_6,
6: uint param_7)
7: 
8: {
9: undefined4 uVar1;
10: int iVar2;
11: long lVar3;
12: FILE *__stream;
13: char *pcVar4;
14: code **ppcVar5;
15: int *piVar6;
16: uint uVar7;
17: long lVar8;
18: undefined8 uVar9;
19: char *pcVar10;
20: uint uVar11;
21: byte bVar12;
22: int iStack112;
23: 
24: bVar12 = 0;
25: iStack112 = (int)param_4;
26: if (((((param_1 == (char *)0x0) || (param_2 == 0)) || (param_3 < 1)) ||
27: (((param_4 & 0xffffffff) >> 0x1f != 0 || (param_5 < 1)))) || (0xb < param_6)) {
28: s_No_error_003a6000._0_8_ = 0x6d49657661536a74;
29: ram0x003a6008 = 0x49203a2928656761;
30: _DAT_003a6010 = 0x612064696c61766e;
31: _DAT_003a6018 = 0x746e656d756772;
32: return 0xffffffff;
33: }
34: lVar3 = tjInitDecompress();
35: if (lVar3 == 0) {
36: return 0xffffffff;
37: }
38: __stream = fopen(param_1,"wb");
39: if (__stream == (FILE *)0x0) {
40: piVar6 = __errno_location();
41: pcVar4 = strerror(*piVar6);
42: snprintf(s_No_error_003a6000,200,"%s\n%s","tjSaveImage(): Cannot open output file",pcVar4);
43: tjDestroy(lVar3);
44: return 0xffffffff;
45: }
46: iVar2 = _setjmp((__jmp_buf_tag *)(lVar3 + 0x528));
47: uVar9 = 0xffffffff;
48: if (iVar2 == 0) {
49: *(undefined4 *)(lVar3 + 0x22c) = 0xca;
50: *(undefined4 *)(lVar3 + 0x250) = 1;
51: lVar8 = lVar3 + 0x208;
52: uVar1 = *(undefined4 *)(&DAT_0018bb40 + (long)(int)param_6 * 4);
53: *(int *)(lVar3 + 0x23c) = param_5;
54: *(undefined4 *)(lVar3 + 0x24c) = 1;
55: *(undefined4 *)(lVar3 + 0x248) = uVar1;
56: *(int *)(lVar3 + 0x238) = param_3;
57: pcVar4 = strrchr(param_1,0x2e);
58: if ((pcVar4 == (char *)0x0) || (iVar2 = strcasecmp(pcVar4,".bmp"), iVar2 != 0)) {
59: ppcVar5 = (code **)FUN_00154f40(lVar8);
60: uVar11 = param_7 >> 1 & 1;
61: if (ppcVar5 == (code **)0x0) {
62: _DAT_003a6028 = 0x74697277;
63: s_No_error_003a6000._0_8_ = 0x6d49657661536a74;
64: _DAT_003a602c = 0x7265;
65: ram0x003a6008 = 0x43203a2928656761;
66: DAT_003a602e = 0;
67: _DAT_003a6010 = 0x746f6e20646c756f;
68: uVar9 = 0xffffffff;
69: _DAT_003a6018 = 0x6c616974696e6920;
70: _DAT_003a6020 = 0x204d505020657a69;
71: goto LAB_0014b325;
72: }
73: }
74: else {
75: ppcVar5 = (code **)FUN_001548d0(lVar8,0,0);
76: uVar11 = (uint)((param_7 & 2) == 0);
77: if (ppcVar5 == (code **)0x0) {
78: lVar8 = 0x32;
79: uVar9 = 0xffffffff;
80: pcVar4 = "tjSaveImage(): Could not initialize bitmap writer";
81: pcVar10 = s_No_error_003a6000;
82: while (lVar8 != 0) {
83: lVar8 = lVar8 + -1;
84: *pcVar10 = *pcVar4;
85: pcVar4 = pcVar4 + (ulong)bVar12 * -2 + 1;
86: pcVar10 = pcVar10 + (ulong)bVar12 * -2 + 1;
87: }
88: goto LAB_0014b325;
89: }
90: }
91: ppcVar5[4] = (code *)__stream;
92: (**ppcVar5)(lVar8);
93: (**(code **)(*(long *)(lVar3 + 0x210) + 0x30))(lVar8);
94: if (iStack112 == 0) {
95: iStack112 = param_3 * *(int *)(&DAT_0018bc40 + (long)(int)param_6 * 4);
96: }
97: uVar7 = *(uint *)(lVar3 + 0x2b0);
98: if (uVar7 < *(uint *)(lVar3 + 0x294)) {
99: iVar2 = *(int *)(&DAT_0018bc40 + (long)(int)param_6 * 4);
100: if (uVar11 == 0) {
101: do {
102: memcpy(*(void **)ppcVar5[5],(void *)(param_2 + (ulong)(uVar7 * iStack112)),
103: (long)(param_3 * iVar2));
104: (*ppcVar5[1])(lVar8,ppcVar5,1);
105: uVar7 = *(int *)(lVar3 + 0x2b0) + 1;
106: *(uint *)(lVar3 + 0x2b0) = uVar7;
107: } while (uVar7 <= *(uint *)(lVar3 + 0x294) && *(uint *)(lVar3 + 0x294) != uVar7);
108: }
109: else {
110: do {
111: memcpy(*(void **)ppcVar5[5],(void *)((ulong)((~uVar7 + param_5) * iStack112) + param_2),
112: (long)(param_3 * iVar2));
113: (*ppcVar5[1])(lVar8,ppcVar5,1);
114: uVar7 = *(int *)(lVar3 + 0x2b0) + 1;
115: *(uint *)(lVar3 + 0x2b0) = uVar7;
116: } while (uVar7 <= *(uint *)(lVar3 + 0x294) && *(uint *)(lVar3 + 0x294) != uVar7);
117: }
118: }
119: (*ppcVar5[2])(lVar8,ppcVar5);
120: uVar9 = 0;
121: }
122: LAB_0014b325:
123: tjDestroy(lVar3);
124: fclose(__stream);
125: return uVar9;
126: }
127: 
