1: 
2: undefined8 FUN_00152460(code **param_1,long param_2)
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
21: if (sVar6 != *(size_t *)(param_2 + 0x40)) {
22: ppcVar4 = (code **)*param_1;
23: *(undefined4 *)(ppcVar4 + 5) = 0x2b;
24: (**ppcVar4)(param_1);
25: }
26: pbVar5 = *(byte **)(param_2 + 0x30);
27: iVar2 = *(int *)(param_1 + 6);
28: if (iVar1 == 0xff) {
29: if (iVar2 != 0) {
30: puVar7 = (undefined *)**(long **)(param_2 + 0x20);
31: pbVar10 = pbVar5;
32: do {
33: pbVar9 = pbVar10 + 1;
34: dVar11 = 1.0 - (double)(uint)*pbVar10 / 255.0;
35: uVar8 = 0xff;
36: if (dVar11 != 1.0) {
37: uVar8 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
38: }
39: *puVar7 = uVar8;
40: puVar7[1] = uVar8;
41: puVar7[2] = uVar8;
42: puVar7[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
43: puVar7 = puVar7 + 4;
44: pbVar10 = pbVar9;
45: } while (pbVar9 != pbVar5 + (ulong)(iVar2 - 1) + 1);
46: return 1;
47: }
48: }
49: else {
50: if (iVar2 != 0) {
51: puVar7 = (undefined *)**(long **)(param_2 + 0x20);
52: pbVar10 = pbVar5;
53: do {
54: pbVar9 = pbVar10 + 1;
55: dVar11 = 1.0 - (double)(uint)*(byte *)(lVar3 + (ulong)*pbVar10) / 255.0;
56: uVar8 = 0xff;
57: if (dVar11 != 1.0) {
58: uVar8 = (undefined)(int)((255.0 - ((dVar11 - dVar11) / (1.0 - dVar11)) * 255.0) + 0.5);
59: }
60: *puVar7 = uVar8;
61: puVar7[1] = uVar8;
62: puVar7[2] = uVar8;
63: puVar7[3] = (char)(int)((255.0 - dVar11 * 255.0) + 0.5);
64: puVar7 = puVar7 + 4;
65: pbVar10 = pbVar9;
66: } while (pbVar9 != pbVar5 + (ulong)(iVar2 - 1) + 1);
67: }
68: }
69: return 1;
70: }
71: 
