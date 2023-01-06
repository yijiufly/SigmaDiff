1: 
2: undefined8 FUN_0016a470(long param_1,long param_2)
3: 
4: {
5: undefined4 uVar1;
6: int iVar2;
7: undefined8 uVar3;
8: long lVar4;
9: undefined *puVar5;
10: uint uVar6;
11: undefined *puVar7;
12: undefined *puVar8;
13: 
14: uVar3 = *(undefined8 *)(param_2 + 0x18);
15: lVar4 = *(long *)(param_2 + 0x48);
16: uVar1 = *(undefined4 *)(param_2 + 0x50);
17: puVar5 = (undefined *)**(undefined8 **)(param_2 + 0x20);
18: iVar2 = *(int *)(param_1 + 0x30);
19: if (iVar2 != 0) {
20: puVar7 = puVar5;
21: do {
22: uVar6 = FUN_00169820(param_1,uVar3,uVar1);
23: puVar8 = puVar7 + 1;
24: *puVar7 = *(undefined *)(lVar4 + (ulong)uVar6);
25: puVar7 = puVar8;
26: } while (puVar8 != puVar5 + (ulong)(iVar2 - 1) + 1);
27: }
28: return 1;
29: }
30: 
