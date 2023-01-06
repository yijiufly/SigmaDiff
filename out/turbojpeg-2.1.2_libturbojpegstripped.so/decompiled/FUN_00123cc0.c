1: 
2: void FUN_00123cc0(long param_1,long param_2,undefined8 param_3,long *param_4)
3: 
4: {
5: long *plVar1;
6: uint uVar2;
7: long lVar3;
8: int iVar4;
9: void *__s;
10: 
11: FUN_00148a00(param_3,0,param_4,0,*(undefined4 *)(param_1 + 0x13c),*(undefined4 *)(param_1 + 0x30))
12: ;
13: uVar2 = *(uint *)(param_1 + 0x30);
14: iVar4 = *(int *)(param_2 + 0x1c) * 8 - uVar2;
15: if ((0 < iVar4) && (0 < *(int *)(param_1 + 0x13c))) {
16: plVar1 = param_4 + (ulong)(*(int *)(param_1 + 0x13c) - 1) + 1;
17: do {
18: lVar3 = *param_4;
19: param_4 = param_4 + 1;
20: __s = (void *)(lVar3 + (ulong)uVar2);
21: memset(__s,(uint)*(byte *)((long)__s + -1),(long)(iVar4 + -1) + 1);
22: } while (plVar1 != param_4);
23: }
24: return;
25: }
26: 
