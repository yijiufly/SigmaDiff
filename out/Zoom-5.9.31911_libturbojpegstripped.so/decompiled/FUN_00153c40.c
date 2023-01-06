1: 
2: undefined8 FUN_00153c40(long param_1,long param_2)
3: 
4: {
5: undefined *puVar1;
6: undefined4 uVar2;
7: undefined8 uVar3;
8: long lVar4;
9: uint uVar5;
10: undefined *puVar6;
11: undefined *puVar7;
12: 
13: uVar3 = *(undefined8 *)(param_2 + 0x18);
14: lVar4 = *(long *)(param_2 + 0x48);
15: uVar2 = *(undefined4 *)(param_2 + 0x50);
16: puVar6 = (undefined *)**(undefined8 **)(param_2 + 0x20);
17: puVar1 = puVar6 + (ulong)(*(int *)(param_1 + 0x30) - 1) + 1;
18: if (*(int *)(param_1 + 0x30) != 0) {
19: do {
20: uVar5 = FUN_00152a10(param_1,uVar3,uVar2);
21: puVar7 = puVar6 + 1;
22: *puVar6 = *(undefined *)(lVar4 + (ulong)uVar5);
23: puVar6 = puVar7;
24: } while (puVar7 != puVar1);
25: }
26: return 1;
27: }
28: 
