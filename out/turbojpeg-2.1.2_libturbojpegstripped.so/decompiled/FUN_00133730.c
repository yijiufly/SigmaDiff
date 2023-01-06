1: 
2: ulong FUN_00133730(long param_1,undefined8 param_2,undefined8 param_3,ulong param_4)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: ulong uVar3;
8: 
9: lVar2 = *(long *)(param_1 + 0x228);
10: if (*(int *)(lVar2 + 0x60) == 0) {
11: uVar3 = (**(code **)(*(long *)(param_1 + 0x230) + 0x18))(param_1,lVar2 + 0x10);
12: if ((int)uVar3 == 0) {
13: return uVar3;
14: }
15: param_4 = param_4 & 0xffffffff;
16: *(undefined4 *)(lVar2 + 0x60) = 1;
17: }
18: uVar1 = *(uint *)(param_1 + 0x1a0);
19: (**(code **)(*(long *)(param_1 + 0x238) + 8))
20: (param_1,lVar2 + 0x10,lVar2 + 100,uVar1,param_2,param_3);
21: if (uVar1 <= *(uint *)(lVar2 + 100)) {
22: *(undefined8 *)(lVar2 + 0x60) = 0;
23: }
24: return param_4;
25: }
26: 
