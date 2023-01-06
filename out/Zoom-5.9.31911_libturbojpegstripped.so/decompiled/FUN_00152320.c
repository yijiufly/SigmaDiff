1: 
2: undefined8 FUN_00152320(code **param_1,long param_2)
3: 
4: {
5: undefined uVar1;
6: undefined uVar2;
7: uint uVar3;
8: int iVar4;
9: long lVar5;
10: code **ppcVar6;
11: undefined *puVar7;
12: size_t sVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: undefined *puVar11;
16: 
17: lVar5 = *(long *)(param_2 + 0x48);
18: uVar3 = *(uint *)(param_2 + 0x50);
19: sVar8 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
20: ;
21: if (sVar8 != *(size_t *)(param_2 + 0x40)) {
22: ppcVar6 = (code **)*param_1;
23: *(undefined4 *)(ppcVar6 + 5) = 0x2b;
24: (**ppcVar6)(param_1);
25: }
26: puVar7 = (undefined *)**(undefined8 **)(param_2 + 0x20);
27: iVar4 = *(int *)(param_1 + 6);
28: if (iVar4 != 0) {
29: puVar9 = *(undefined **)(param_2 + 0x30);
30: puVar11 = puVar7;
31: do {
32: uVar1 = *puVar9;
33: uVar2 = puVar9[1];
34: if (uVar3 < CONCAT11(uVar1,uVar2)) {
35: ppcVar6 = (code **)*param_1;
36: *(undefined4 *)(ppcVar6 + 5) = 0x3f9;
37: (**ppcVar6)(param_1);
38: }
39: *puVar11 = *(undefined *)(lVar5 + (ulong)(uint)CONCAT11(uVar1,uVar2));
40: uVar1 = puVar9[2];
41: uVar2 = puVar9[3];
42: if (uVar3 < CONCAT11(uVar1,uVar2)) {
43: ppcVar6 = (code **)*param_1;
44: *(undefined4 *)(ppcVar6 + 5) = 0x3f9;
45: (**ppcVar6)(param_1);
46: }
47: puVar11[1] = *(undefined *)(lVar5 + (ulong)(uint)CONCAT11(uVar1,uVar2));
48: uVar1 = puVar9[4];
49: uVar2 = puVar9[5];
50: if (uVar3 < CONCAT11(uVar1,uVar2)) {
51: ppcVar6 = (code **)*param_1;
52: *(undefined4 *)(ppcVar6 + 5) = 0x3f9;
53: (**ppcVar6)(param_1);
54: }
55: puVar10 = puVar11 + 3;
56: puVar11[2] = *(undefined *)(lVar5 + (ulong)(uint)CONCAT11(uVar1,uVar2));
57: puVar9 = puVar9 + 6;
58: puVar11 = puVar10;
59: } while (puVar10 != puVar7 + (ulong)(iVar4 - 1) * 3 + 3);
60: }
61: return 1;
62: }
63: 
