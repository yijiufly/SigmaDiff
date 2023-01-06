1: 
2: void FUN_00128c30(long param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: int iVar3;
8: 
9: lVar2 = *(long *)(param_1 + 0x228);
10: if (*(int *)(lVar2 + 0x60) == 0) {
11: iVar3 = (**(code **)(*(long *)(param_1 + 0x230) + 0x18))(param_1,lVar2 + 0x10);
12: if (iVar3 == 0) {
13: return;
14: }
15: *(undefined4 *)(lVar2 + 0x60) = 1;
16: }
17: uVar1 = *(uint *)(param_1 + 0x1a0);
18: (**(code **)(*(long *)(param_1 + 0x238) + 8))
19: (param_1,lVar2 + 0x10,lVar2 + 100,uVar1,param_2,param_3,param_4);
20: if (uVar1 < *(uint *)(lVar2 + 100) || uVar1 == *(uint *)(lVar2 + 100)) {
21: *(undefined4 *)(lVar2 + 0x60) = 0;
22: *(undefined4 *)(lVar2 + 100) = 0;
23: }
24: return;
25: }
26: 
