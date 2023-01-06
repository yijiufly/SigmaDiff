1: 
2: undefined8 FUN_00168ac0(code **param_1,long param_2)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: code **ppcVar3;
8: undefined *puVar4;
9: size_t sVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: byte *pbVar8;
13: 
14: lVar2 = *(long *)(param_2 + 0x48);
15: sVar5 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
16: ;
17: if (*(size_t *)(param_2 + 0x40) != sVar5) {
18: ppcVar3 = (code **)*param_1;
19: *(undefined4 *)(ppcVar3 + 5) = 0x2b;
20: (**ppcVar3)(param_1);
21: }
22: iVar1 = *(int *)(param_1 + 6);
23: puVar4 = (undefined *)**(undefined8 **)(param_2 + 0x20);
24: if (iVar1 != 0) {
25: puVar6 = puVar4;
26: pbVar8 = *(byte **)(param_2 + 0x30);
27: do {
28: puVar7 = puVar6 + 1;
29: *puVar6 = *(undefined *)(lVar2 + (ulong)*pbVar8);
30: puVar6 = puVar7;
31: pbVar8 = pbVar8 + 1;
32: } while (puVar7 != puVar4 + (ulong)(iVar1 - 1) + 1);
33: }
34: return 1;
35: }
36: 
