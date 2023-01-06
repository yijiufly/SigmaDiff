1: 
2: undefined8 FUN_0012b9a0(long *param_1,int param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: int iVar3;
8: 
9: lVar1 = *param_1;
10: iVar3 = *(int *)((long)param_1 + 0x21c);
11: *(undefined4 *)(lVar1 + 0x28) = 0x79;
12: *(int *)(lVar1 + 0x2c) = iVar3;
13: *(int *)(*param_1 + 0x30) = param_2;
14: (**(code **)(*param_1 + 8))(param_1,0xffffffff);
15: do {
16: if (0xbf < iVar3) {
17: if (((7 < iVar3 - 0xd0U) || ((param_2 + 1U & 7) + 0xd0 == iVar3)) ||
18: ((param_2 + 2U & 7) + 0xd0 == iVar3)) {
19: lVar1 = *param_1;
20: *(int *)(lVar1 + 0x2c) = iVar3;
21: *(undefined4 *)(lVar1 + 0x28) = 0x61;
22: *(undefined4 *)(*param_1 + 0x30) = 3;
23: (**(code **)(*param_1 + 8))(param_1,4);
24: return 1;
25: }
26: if (((param_2 - 1U & 7) + 0xd0 != iVar3) && ((param_2 - 2U & 7) + 0xd0 != iVar3)) {
27: lVar1 = *param_1;
28: *(int *)(lVar1 + 0x2c) = iVar3;
29: *(undefined4 *)(lVar1 + 0x28) = 0x61;
30: *(undefined4 *)(*param_1 + 0x30) = 1;
31: (**(code **)(*param_1 + 8))(param_1,4);
32: *(undefined4 *)((long)param_1 + 0x21c) = 0;
33: return 1;
34: }
35: }
36: lVar1 = *param_1;
37: *(int *)(lVar1 + 0x2c) = iVar3;
38: lVar2 = *param_1;
39: *(undefined4 *)(lVar1 + 0x28) = 0x61;
40: *(undefined4 *)(lVar2 + 0x30) = 2;
41: (**(code **)(*param_1 + 8))(param_1,4);
42: iVar3 = FUN_00129b00(param_1);
43: if (iVar3 == 0) {
44: return 0;
45: }
46: iVar3 = *(int *)((long)param_1 + 0x21c);
47: } while( true );
48: }
49: 
