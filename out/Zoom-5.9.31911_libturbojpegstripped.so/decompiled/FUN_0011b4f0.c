1: 
2: void FUN_0011b4f0(long param_1,long param_2,undefined8 param_3,long *param_4)
3: 
4: {
5: long *plVar1;
6: uint uVar2;
7: uint uVar3;
8: void *__s;
9: 
10: FUN_0013be50(param_3,0,param_4,0,*(undefined4 *)(param_1 + 0x13c),*(undefined4 *)(param_1 + 0x30))
11: ;
12: uVar2 = *(uint *)(param_1 + 0x30);
13: uVar3 = *(int *)(param_2 + 0x1c) * 8 - uVar2;
14: if ((0 < (int)uVar3) && (0 < *(int *)(param_1 + 0x13c))) {
15: plVar1 = param_4 + (ulong)(*(int *)(param_1 + 0x13c) - 1) + 1;
16: do {
17: __s = (void *)((ulong)uVar2 + *param_4);
18: param_4 = param_4 + 1;
19: memset(__s,(uint)*(byte *)((long)__s + -1),(ulong)uVar3);
20: } while (param_4 != plVar1);
21: }
22: return;
23: }
24: 
