1: 
2: undefined8 FUN_001528f0(code **param_1,long param_2)
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
28: puVar10 = puVar7;
29: puVar11 = *(undefined **)(param_2 + 0x30);
30: if (iVar4 != 0) {
31: do {
32: uVar1 = *puVar11;
33: uVar2 = puVar11[1];
34: if (uVar3 < CONCAT11(uVar1,uVar2)) {
35: ppcVar6 = (code **)*param_1;
36: *(undefined4 *)(ppcVar6 + 5) = 0x3f9;
37: (**ppcVar6)(param_1);
38: }
39: puVar9 = puVar10 + 1;
40: *puVar10 = *(undefined *)(lVar5 + (ulong)(uint)CONCAT11(uVar1,uVar2));
41: puVar10 = puVar9;
42: puVar11 = puVar11 + 2;
43: } while (puVar9 != puVar7 + (ulong)(iVar4 - 1) + 1);
44: }
45: return 1;
46: }
47: 
