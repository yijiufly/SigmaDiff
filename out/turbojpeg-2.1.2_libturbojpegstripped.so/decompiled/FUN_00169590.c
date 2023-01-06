1: 
2: undefined8 FUN_00169590(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: long lVar3;
8: code **ppcVar4;
9: undefined *puVar5;
10: size_t sVar6;
11: ushort uVar7;
12: ushort *puVar8;
13: undefined *puVar9;
14: undefined *puVar10;
15: 
16: lVar3 = *(long *)(param_2 + 0x48);
17: uVar1 = *(uint *)(param_2 + 0x50);
18: sVar6 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
19: ;
20: if (*(size_t *)(param_2 + 0x40) != sVar6) {
21: ppcVar4 = (code **)*param_1;
22: *(undefined4 *)(ppcVar4 + 5) = 0x2b;
23: (**ppcVar4)(param_1);
24: }
25: iVar2 = *(int *)(param_1 + 6);
26: puVar5 = (undefined *)**(undefined8 **)(param_2 + 0x20);
27: if (iVar2 != 0) {
28: puVar8 = *(ushort **)(param_2 + 0x30);
29: puVar9 = puVar5;
30: do {
31: uVar7 = *puVar8 << 8 | *puVar8 >> 8;
32: if (uVar1 < uVar7) {
33: ppcVar4 = (code **)*param_1;
34: *(undefined4 *)(ppcVar4 + 5) = 0x3f9;
35: (**ppcVar4)(param_1);
36: }
37: puVar10 = puVar9 + 1;
38: *puVar9 = *(undefined *)(lVar3 + (ulong)uVar7);
39: puVar8 = puVar8 + 1;
40: puVar9 = puVar10;
41: } while (puVar5 + (ulong)(iVar2 - 1) + 1 != puVar10);
42: }
43: return 1;
44: }
45: 
