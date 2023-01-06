1: 
2: void FUN_00153ce0(long param_1,long param_2)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: uint uVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: char *pcVar8;
13: char **ppcVar9;
14: void *pvVar10;
15: ushort *__src;
16: char *pcVar11;
17: ulong uVar12;
18: char *pcVar13;
19: char *__dest;
20: char *pcVar14;
21: double dVar15;
22: 
23: if (*(int *)(param_2 + 0x58) == 0) {
24: uVar3 = *(uint *)(param_1 + 0x40);
25: __dest = *(char **)(param_2 + 0x60);
26: __src = **(ushort ***)(param_2 + 0x28);
27: }
28: else {
29: ppcVar9 = (char **)(**(code **)(*(long *)(param_1 + 8) + 0x38))
30: (param_1,*(undefined8 *)(param_2 + 0x40),
31: *(undefined4 *)(param_2 + 0x54),1);
32: uVar3 = *(uint *)(param_1 + 0x40);
33: __dest = *ppcVar9;
34: *(int *)(param_2 + 0x54) = *(int *)(param_2 + 0x54) + 1;
35: __src = **(ushort ***)(param_2 + 0x28);
36: }
37: if (uVar3 == 8) {
38: pvVar10 = memcpy(__dest,__src,(ulong)*(uint *)(param_2 + 0x4c));
39: __dest = (char *)((ulong)(uint)(*(int *)(param_1 + 0x88) * 3) + (long)pvVar10);
40: }
41: else {
42: uVar12 = (ulong)uVar3;
43: if (uVar3 == 0x10) {
44: if (*(int *)(param_1 + 0x88) != 0) {
45: pcVar14 = __dest + (ulong)(*(int *)(param_1 + 0x88) - 1) * 3 + 3;
46: pcVar8 = __dest;
47: do {
48: pcVar13 = pcVar8 + 3;
49: *pcVar8 = (char)*__src << 3;
50: pcVar8[1] = (byte)(*__src >> 3) & 0xfc;
51: pcVar8[2] = (byte)(*__src >> 8) & 0xf8;
52: __src = __src + 1;
53: pcVar8 = pcVar13;
54: __dest = pcVar14;
55: } while (pcVar13 != pcVar14);
56: }
57: }
58: else {
59: if (uVar3 == 4) {
60: if (*(int *)(param_1 + 0x88) != 0) {
61: pcVar14 = __dest + (ulong)(*(int *)(param_1 + 0x88) - 1) * 3 + 3;
62: pcVar8 = __dest;
63: do {
64: bVar1 = *(byte *)((long)__src + 1);
65: bVar2 = *(byte *)(__src + 1);
66: pcVar13 = pcVar8 + 3;
67: dVar15 = (double)(uint)*(byte *)((long)__src + 3);
68: pcVar8[2] = (char)(int)(((double)(uint)*(byte *)__src * dVar15) / 255.0 + 0.5);
69: pcVar8[1] = (char)(int)(((double)(uint)bVar1 * dVar15) / 255.0 + 0.5);
70: *pcVar8 = (char)(int)(((double)(uint)bVar2 * dVar15) / 255.0 + 0.5);
71: __src = __src + 2;
72: pcVar8 = pcVar13;
73: __dest = pcVar14;
74: } while (pcVar13 != pcVar14);
75: }
76: }
77: else {
78: iVar4 = *(int *)(&DAT_0018c620 + uVar12 * 4);
79: iVar5 = *(int *)(&DAT_0018c5c0 + uVar12 * 4);
80: iVar6 = *(int *)(&DAT_0018c560 + uVar12 * 4);
81: iVar7 = *(int *)(&DAT_0018c500 + uVar12 * 4);
82: if (*(int *)(param_1 + 0x88) != 0) {
83: pcVar13 = __dest + (ulong)(*(int *)(param_1 + 0x88) - 1) * 3 + 3;
84: pcVar8 = (char *)((long)__src + (long)iVar6);
85: pcVar14 = __dest;
86: do {
87: pcVar11 = pcVar14 + 3;
88: *pcVar14 = *pcVar8;
89: pcVar14[1] = (pcVar8 + -(long)iVar6)[iVar5];
90: pcVar14[2] = (pcVar8 + -(long)iVar6)[iVar4];
91: pcVar8 = pcVar8 + iVar7;
92: pcVar14 = pcVar11;
93: __dest = pcVar13;
94: } while (pcVar11 != pcVar13);
95: }
96: }
97: }
98: }
99: if (0 < (int)*(uint *)(param_2 + 0x50)) {
100: memset(__dest,0,(ulong)*(uint *)(param_2 + 0x50));
101: }
102: if (*(int *)(param_2 + 0x58) != 0) {
103: return;
104: }
105: fwrite(*(void **)(param_2 + 0x60),1,(ulong)*(uint *)(param_2 + 0x4c),*(FILE **)(param_2 + 0x20));
106: return;
107: }
108: 
