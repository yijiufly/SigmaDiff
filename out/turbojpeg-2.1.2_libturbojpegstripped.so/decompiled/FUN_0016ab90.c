1: 
2: void FUN_0016ab90(long param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: uint uVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: int iVar8;
13: char **ppcVar9;
14: ulong uVar10;
15: void *pvVar11;
16: char *__dest;
17: char *pcVar12;
18: ushort *__src;
19: char *pcVar13;
20: char *pcVar14;
21: double dVar15;
22: 
23: if (*(int *)(param_2 + 0x58) == 0) {
24: __dest = *(char **)(param_2 + 0x60);
25: }
26: else {
27: ppcVar9 = (char **)(**(code **)(*(long *)(param_1 + 8) + 0x38))
28: (param_1,*(undefined8 *)(param_2 + 0x40),
29: *(undefined4 *)(param_2 + 0x54),1);
30: *(int *)(param_2 + 0x54) = *(int *)(param_2 + 0x54) + 1;
31: __dest = *ppcVar9;
32: }
33: __src = **(ushort ***)(param_2 + 0x28);
34: uVar3 = *(uint *)(param_1 + 0x40);
35: uVar10 = (ulong)uVar3;
36: if (uVar3 == 8) {
37: pvVar11 = memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
38: __dest = (char *)((long)pvVar11 + (ulong)(uint)(*(int *)(param_1 + 0x88) * 3));
39: }
40: else {
41: iVar4 = *(int *)(param_1 + 0x88);
42: if (uVar3 == 0x10) {
43: if (iVar4 != 0) {
44: pcVar13 = __dest + (ulong)(iVar4 - 1) * 3 + 3;
45: pcVar12 = __dest;
46: do {
47: __dest = pcVar12 + 3;
48: *pcVar12 = (char)*__src << 3;
49: pcVar12[1] = (byte)(*__src >> 3) & 0xfc;
50: pcVar12[2] = (byte)(*__src >> 8) & 0xf8;
51: pcVar12 = __dest;
52: __src = __src + 1;
53: } while (__dest != pcVar13);
54: }
55: }
56: else {
57: if (uVar3 == 4) {
58: if (iVar4 != 0) {
59: pcVar13 = __dest + (ulong)(iVar4 - 1) * 3 + 3;
60: pcVar12 = __dest;
61: do {
62: bVar1 = *(byte *)((long)__src + 1);
63: bVar2 = *(byte *)(__src + 1);
64: __dest = pcVar12 + 3;
65: dVar15 = (double)(uint)*(byte *)((long)__src + 3);
66: pcVar12[2] = (char)(int)(((double)(uint)*(byte *)__src * dVar15) / 255.0 + 0.5);
67: *pcVar12 = (char)(int)(((double)(uint)bVar2 * dVar15) / 255.0 + 0.5);
68: pcVar12[1] = (char)(int)(((double)(uint)bVar1 * dVar15) / 255.0 + 0.5);
69: pcVar12 = __dest;
70: __src = __src + 2;
71: } while (__dest != pcVar13);
72: }
73: }
74: else {
75: iVar5 = *(int *)(&DAT_001909e0 + uVar10 * 4);
76: iVar6 = *(int *)(&DAT_001908c0 + uVar10 * 4);
77: iVar7 = *(int *)(&DAT_00190980 + uVar10 * 4);
78: iVar8 = *(int *)(&DAT_00190920 + uVar10 * 4);
79: if (iVar4 != 0) {
80: pcVar14 = __dest + (ulong)(iVar4 - 1) * 3 + 3;
81: pcVar12 = __dest;
82: pcVar13 = (char *)((long)__src + (long)iVar8);
83: do {
84: __dest = pcVar12 + 3;
85: *pcVar12 = *pcVar13;
86: pcVar12[1] = (pcVar13 + -(long)iVar8)[iVar7];
87: pcVar12[2] = (pcVar13 + -(long)iVar8)[iVar5];
88: pcVar12 = __dest;
89: pcVar13 = pcVar13 + iVar6;
90: } while (__dest != pcVar14);
91: }
92: }
93: }
94: }
95: if (0 < *(int *)(param_2 + 0x50)) {
96: memset(__dest,0,(ulong)(*(int *)(param_2 + 0x50) - 1) + 1);
97: }
98: if (*(int *)(param_2 + 0x58) == 0) {
99: fwrite(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),*(FILE **)(param_2 + 0x20))
100: ;
101: return;
102: }
103: return;
104: }
105: 
