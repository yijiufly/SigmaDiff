1: 
2: undefined4
3: tjSaveImage(char *param_1,long param_2,int param_3,int param_4,int param_5,uint param_6,uint param_7
4: )
5: 
6: {
7: int iVar1;
8: long lVar2;
9: long lVar3;
10: char *pcVar4;
11: code **ppcVar5;
12: int *piVar6;
13: undefined8 uVar7;
14: undefined4 *puVar8;
15: uint uVar9;
16: uint uVar10;
17: undefined8 uVar11;
18: undefined4 uStack124;
19: FILE *pFStack48;
20: 
21: uStack124 = 0;
22: if (((((param_1 == (char *)0x0) || (param_2 == 0)) || (param_3 < 1)) ||
23: ((param_4 < 0 || (param_5 < 1)))) || (0xb < param_6)) {
24: puVar8 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
25: *puVar8 = 0x61536a74;
26: puVar8[1] = 0x6d496576;
27: puVar8[2] = 0x28656761;
28: puVar8[3] = 0x49203a29;
29: puVar8[4] = 0x6c61766e;
30: puVar8[5] = 0x61206469;
31: puVar8[6] = 0x6d756772;
32: puVar8[7] = 0x746e65;
33: return 0xffffffff;
34: }
35: lVar2 = tjInitDecompress();
36: if (lVar2 == 0) {
37: return 0xffffffff;
38: }
39: lVar3 = lVar2 + 0x208;
40: pFStack48 = fopen(param_1,"wb");
41: if (pFStack48 == (FILE *)0x0) {
42: piVar6 = __errno_location();
43: pcVar4 = strerror(*piVar6);
44: uVar11 = 0x1597ba;
45: uVar7 = __tls_get_addr(&PTR_00398fc0);
46: __snprintf_chk(uVar7,200,1,200,"%s\n%s","tjSaveImage(): Cannot open output file",pcVar4,uVar11);
47: pFStack48 = (FILE *)0x0;
48: uStack124 = 0xffffffff;
49: }
50: else {
51: iVar1 = _setjmp((__jmp_buf_tag *)(lVar2 + 0x528));
52: if (iVar1 == 0) {
53: *(undefined4 *)(lVar2 + 0x248) = *(undefined4 *)(&DAT_0018fc80 + (long)(int)param_6 * 4);
54: *(int *)(lVar2 + 0x23c) = param_5;
55: *(undefined4 *)(lVar2 + 0x22c) = 0xca;
56: *(int *)(lVar2 + 0x238) = param_3;
57: *(undefined8 *)(lVar2 + 0x24c) = 0x100000001;
58: pcVar4 = strrchr(param_1,0x2e);
59: if ((pcVar4 == (char *)0x0) || (iVar1 = strcasecmp(pcVar4,".bmp"), iVar1 != 0)) {
60: ppcVar5 = (code **)FUN_0016bd50(lVar3);
61: uVar10 = param_7 >> 1 & 1;
62: if (ppcVar5 != (code **)0x0) goto LAB_0015960c;
63: puVar8 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
64: *(undefined8 *)(puVar8 + 8) = 0x204d505020657a69;
65: puVar8[10] = 0x74697277;
66: *puVar8 = 0x61536a74;
67: puVar8[1] = 0x6d496576;
68: puVar8[2] = 0x28656761;
69: puVar8[3] = 0x43203a29;
70: *(undefined2 *)(puVar8 + 0xb) = 0x7265;
71: *(undefined *)((long)puVar8 + 0x2e) = 0;
72: uStack124 = 0xffffffff;
73: puVar8[4] = 0x646c756f;
74: puVar8[5] = 0x746f6e20;
75: puVar8[6] = 0x696e6920;
76: puVar8[7] = 0x6c616974;
77: }
78: else {
79: ppcVar5 = (code **)FUN_0016b740(lVar3,0,0);
80: uVar10 = (uint)((param_7 & 2) == 0);
81: if (ppcVar5 == (code **)0x0) {
82: puVar8 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
83: *(undefined2 *)(puVar8 + 0xc) = 0x72;
84: uStack124 = 0xffffffff;
85: *puVar8 = 0x61536a74;
86: puVar8[1] = 0x6d496576;
87: puVar8[2] = 0x28656761;
88: puVar8[3] = 0x43203a29;
89: puVar8[4] = 0x646c756f;
90: puVar8[5] = 0x746f6e20;
91: puVar8[6] = 0x696e6920;
92: puVar8[7] = 0x6c616974;
93: puVar8[8] = 0x20657a69;
94: puVar8[9] = 0x6d746962;
95: puVar8[10] = 0x77207061;
96: puVar8[0xb] = 0x65746972;
97: }
98: else {
99: LAB_0015960c:
100: ppcVar5[4] = (code *)pFStack48;
101: (**ppcVar5)(lVar3);
102: (**(code **)(*(long *)(lVar2 + 0x210) + 0x30))(lVar3);
103: if (param_4 == 0) {
104: param_4 = param_3 * *(int *)(&DAT_0018fd80 + (long)(int)param_6 * 4);
105: }
106: uVar9 = *(uint *)(lVar2 + 0x2b0);
107: if (uVar9 <= *(uint *)(lVar2 + 0x294) && *(uint *)(lVar2 + 0x294) != uVar9) {
108: iVar1 = *(int *)(&DAT_0018fd80 + (long)(int)param_6 * 4);
109: if (uVar10 == 0) {
110: do {
111: memcpy(*(void **)ppcVar5[5],(void *)((ulong)(uVar9 * param_4) + param_2),
112: (long)(param_3 * iVar1));
113: (*ppcVar5[1])(lVar3,ppcVar5,1);
114: uVar9 = *(int *)(lVar2 + 0x2b0) + 1;
115: *(uint *)(lVar2 + 0x2b0) = uVar9;
116: } while (uVar9 <= *(uint *)(lVar2 + 0x294) && *(uint *)(lVar2 + 0x294) != uVar9);
117: }
118: else {
119: do {
120: memcpy(*(void **)ppcVar5[5],
121: (void *)((ulong)((~uVar9 + param_5) * param_4) + param_2),
122: (long)(param_3 * iVar1));
123: (*ppcVar5[1])(lVar3,ppcVar5,1);
124: uVar9 = *(int *)(lVar2 + 0x2b0) + 1;
125: *(uint *)(lVar2 + 0x2b0) = uVar9;
126: } while (uVar9 < *(uint *)(lVar2 + 0x294));
127: }
128: }
129: (*ppcVar5[2])(lVar3,ppcVar5);
130: }
131: }
132: }
133: else {
134: uStack124 = 0xffffffff;
135: }
136: if (lVar2 == 0) goto LAB_00159807;
137: }
138: tjDestroy(lVar2);
139: LAB_00159807:
140: if (pFStack48 != (FILE *)0x0) {
141: fclose(pFStack48);
142: }
143: return uStack124;
144: }
145: 
