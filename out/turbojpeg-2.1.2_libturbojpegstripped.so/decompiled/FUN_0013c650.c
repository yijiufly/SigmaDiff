1: 
2: void FUN_0013c650(long param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
3: undefined8 param_5,int *param_6)
4: 
5: {
6: uint uVar1;
7: long lVar2;
8: undefined8 uVar3;
9: undefined4 uVar4;
10: uint uVar5;
11: 
12: lVar2 = *(long *)(param_1 + 0x238);
13: uVar1 = *(uint *)(lVar2 + 0x28);
14: uVar4 = *(undefined4 *)(lVar2 + 0x20);
15: if (uVar1 == 0) {
16: uVar3 = (**(code **)(*(long *)(param_1 + 8) + 0x38))
17: (param_1,*(undefined8 *)(lVar2 + 0x10),*(undefined4 *)(lVar2 + 0x24),uVar4,1);
18: uVar1 = *(uint *)(lVar2 + 0x28);
19: uVar4 = *(undefined4 *)(lVar2 + 0x20);
20: *(undefined8 *)(lVar2 + 0x18) = uVar3;
21: }
22: else {
23: uVar3 = *(undefined8 *)(lVar2 + 0x18);
24: }
25: (**(code **)(*(long *)(param_1 + 0x260) + 8))
26: (param_1,param_2,param_3,param_4,uVar3,lVar2 + 0x28,uVar4);
27: uVar5 = *(uint *)(lVar2 + 0x28);
28: if (uVar1 < uVar5) {
29: (**(code **)(*(long *)(param_1 + 0x270) + 8))
30: (param_1,*(long *)(lVar2 + 0x18) + (ulong)uVar1 * 8,0);
31: *param_6 = *param_6 + (uVar5 - uVar1);
32: uVar5 = *(uint *)(lVar2 + 0x28);
33: }
34: if (*(uint *)(lVar2 + 0x20) <= uVar5) {
35: *(int *)(lVar2 + 0x24) = *(int *)(lVar2 + 0x24) + *(uint *)(lVar2 + 0x20);
36: *(undefined4 *)(lVar2 + 0x28) = 0;
37: }
38: return;
39: }
40: 
