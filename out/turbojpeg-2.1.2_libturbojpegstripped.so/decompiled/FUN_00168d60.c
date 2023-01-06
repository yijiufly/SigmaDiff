1: 
2: undefined8 FUN_00168d60(code **param_1,long param_2)
3: 
4: {
5: int iVar1;
6: int iVar2;
7: long lVar3;
8: code **ppcVar4;
9: byte *pbVar5;
10: size_t sVar6;
11: undefined *puVar7;
12: undefined uVar8;
13: byte *pbVar9;
14: byte *pbVar10;
15: double dVar11;
16: 
17: lVar3 = *(long *)(param_2 + 0x48);
18: iVar1 = *(int *)(param_2 + 0x50);
19: sVar6 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
20: ;
21: if (*(size_t *)(param_2 + 0x40) != sVar6) {
22: ppcVar4 = (code **)*param_1;
23: *(undefined4 *)(ppcVar4 + 5) = 0x2b;
24: (**ppcVar4)(param_1);
25: }
26: pbVar5 = *(byte **)(param_2 + 0x30);
27: iVar2 = *(int *)(param_1 + 6);
28: if (iVar1 == 0xff) {
29: if (iVar2 != 0) {
30: puVar7 = (undefined *)**(undefined8 **)(param_2 + 0x20);
31: pbVar10 = pbVar5;
32: do {
33: while( true ) {
34: pbVar9 = pbVar10 + 1;
35: dVar11 = 1.0 - (double)(uint)*pbVar10 / 255.0;
36: pbVar10 = pbVar9;
37: if (dVar11 == 1.0) break;
38: uVar8 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
39: *puVar7 = uVar8;
40: puVar7[1] = uVar8;
41: puVar7[2] = uVar8;
42: puVar7[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
43: puVar7 = puVar7 + 4;
44: if (pbVar9 == pbVar5 + (ulong)(iVar2 - 1) + 1) {
45: return 1;
46: }
47: }
48: *puVar7 = 0xff;
49: puVar7[1] = 0xff;
50: puVar7[2] = 0xff;
51: puVar7[3] = 0;
52: puVar7 = puVar7 + 4;
53: } while (pbVar9 != pbVar5 + (ulong)(iVar2 - 1) + 1);
54: return 1;
55: }
56: }
57: else {
58: if (iVar2 != 0) {
59: puVar7 = (undefined *)**(undefined8 **)(param_2 + 0x20);
60: pbVar10 = pbVar5;
61: do {
62: while( true ) {
63: pbVar9 = pbVar10 + 1;
64: dVar11 = 1.0 - (double)(uint)*(byte *)(lVar3 + (ulong)*pbVar10) / 255.0;
65: pbVar10 = pbVar9;
66: if (dVar11 != 1.0) break;
67: *puVar7 = 0xff;
68: puVar7[1] = 0xff;
69: puVar7[2] = 0xff;
70: puVar7[3] = 0;
71: puVar7 = puVar7 + 4;
72: if (pbVar9 == pbVar5 + (ulong)(iVar2 - 1) + 1) {
73: return 1;
74: }
75: }
76: uVar8 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
77: *puVar7 = uVar8;
78: puVar7[1] = uVar8;
79: puVar7[2] = uVar8;
80: puVar7[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
81: puVar7 = puVar7 + 4;
82: } while (pbVar9 != pbVar5 + (ulong)(iVar2 - 1) + 1);
83: }
84: }
85: return 1;
86: }
87: 
