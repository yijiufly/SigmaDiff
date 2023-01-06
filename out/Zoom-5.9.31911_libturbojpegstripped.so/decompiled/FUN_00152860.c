1: 
2: undefined8 FUN_00152860(code **param_1,long param_2)
3: 
4: {
5: undefined *puVar1;
6: long lVar2;
7: code **ppcVar3;
8: size_t sVar4;
9: undefined *puVar5;
10: undefined *puVar6;
11: byte *pbVar7;
12: 
13: lVar2 = *(long *)(param_2 + 0x48);
14: sVar4 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18))
15: ;
16: if (sVar4 != *(size_t *)(param_2 + 0x40)) {
17: ppcVar3 = (code **)*param_1;
18: *(undefined4 *)(ppcVar3 + 5) = 0x2b;
19: (**ppcVar3)(param_1);
20: }
21: pbVar7 = *(byte **)(param_2 + 0x30);
22: puVar5 = (undefined *)**(undefined8 **)(param_2 + 0x20);
23: puVar1 = puVar5 + (ulong)(*(int *)(param_1 + 6) - 1) + 1;
24: if (*(int *)(param_1 + 6) != 0) {
25: do {
26: puVar6 = puVar5 + 1;
27: *puVar5 = *(undefined *)(lVar2 + (ulong)*pbVar7);
28: puVar5 = puVar6;
29: pbVar7 = pbVar7 + 1;
30: } while (puVar6 != puVar1);
31: }
32: return 1;
33: }
34: 
