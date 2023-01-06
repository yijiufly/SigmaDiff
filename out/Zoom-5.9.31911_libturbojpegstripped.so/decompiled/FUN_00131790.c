1: 
2: void FUN_00131790(long param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
3: undefined8 param_5,int *param_6)
4: 
5: {
6: uint uVar1;
7: long lVar2;
8: undefined8 uVar3;
9: uint uVar4;
10: 
11: lVar2 = *(long *)(param_1 + 0x238);
12: uVar1 = *(uint *)(lVar2 + 0x28);
13: if (uVar1 == 0) {
14: uVar3 = (**(code **)(*(long *)(param_1 + 8) + 0x38))
15: (param_1,*(undefined8 *)(lVar2 + 0x10),*(undefined4 *)(lVar2 + 0x24),
16: *(undefined4 *)(lVar2 + 0x20),1);
17: uVar1 = *(uint *)(lVar2 + 0x28);
18: *(undefined8 *)(lVar2 + 0x18) = uVar3;
19: }
20: else {
21: uVar3 = *(undefined8 *)(lVar2 + 0x18);
22: }
23: (**(code **)(*(long *)(param_1 + 0x260) + 8))
24: (param_1,param_2,param_3,param_4,uVar3,lVar2 + 0x28,*(undefined4 *)(lVar2 + 0x20));
25: uVar4 = *(uint *)(lVar2 + 0x28);
26: if (uVar1 < uVar4) {
27: (**(code **)(*(long *)(param_1 + 0x270) + 8))
28: (param_1,*(long *)(lVar2 + 0x18) + (ulong)uVar1 * 8,0);
29: *param_6 = *param_6 + (uVar4 - uVar1);
30: uVar4 = *(uint *)(lVar2 + 0x28);
31: }
32: if (*(uint *)(lVar2 + 0x20) <= uVar4) {
33: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + *(uint *)(lVar2 + 0x20);
34: *(undefined4 *)(lVar2 + 0x28) = 0;
35: }
36: return;
37: }
38: 
