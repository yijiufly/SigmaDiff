1: 
2: undefined8 FUN_0012b6a0(long *param_1)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: 
8: iVar2 = *(int *)((long)param_1 + 0x21c);
9: if (iVar2 == 0) {
10: iVar2 = FUN_00129b00();
11: if (iVar2 == 0) {
12: return 0;
13: }
14: iVar2 = *(int *)((long)param_1 + 0x21c);
15: }
16: if (*(int *)(param_1[0x49] + 0x20) + 0xd0 == iVar2) {
17: lVar1 = *param_1;
18: *(int *)(lVar1 + 0x2c) = *(int *)(param_1[0x49] + 0x20);
19: *(undefined4 *)(lVar1 + 0x28) = 0x62;
20: (**(code **)(*param_1 + 8))(param_1,3);
21: *(undefined4 *)((long)param_1 + 0x21c) = 0;
22: }
23: else {
24: iVar2 = (**(code **)(param_1[5] + 0x28))(param_1);
25: if (iVar2 == 0) {
26: return 0;
27: }
28: }
29: *(uint *)(param_1[0x49] + 0x20) = *(int *)(param_1[0x49] + 0x20) + 1U & 7;
30: return 1;
31: }
32: 
