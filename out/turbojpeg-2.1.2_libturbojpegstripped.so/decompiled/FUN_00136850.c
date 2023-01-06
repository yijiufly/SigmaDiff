1: 
2: undefined8 FUN_00136850(long *param_1,int param_2)
3: 
4: {
5: long lVar1;
6: undefined8 uVar2;
7: int iVar3;
8: 
9: iVar3 = *(int *)((long)param_1 + 0x21c);
10: lVar1 = *param_1;
11: *(int *)(lVar1 + 0x30) = param_2;
12: *(undefined4 *)(lVar1 + 0x28) = 0x79;
13: *(int *)(lVar1 + 0x2c) = iVar3;
14: (**(code **)(lVar1 + 8))(param_1,0xffffffff);
15: do {
16: if (0xbf < iVar3) {
17: if (((7 < iVar3 - 0xd0U) || (iVar3 == (param_2 + 1U & 7) + 0xd0)) ||
18: (iVar3 == (param_2 + 2U & 7) + 0xd0)) {
19: lVar1 = *param_1;
20: *(undefined4 *)(lVar1 + 0x28) = 0x61;
21: *(int *)(lVar1 + 0x2c) = iVar3;
22: *(undefined4 *)(lVar1 + 0x30) = 3;
23: (**(code **)(lVar1 + 8))(param_1,4);
24: return 1;
25: }
26: if ((iVar3 != (param_2 - 1U & 7) + 0xd0) && (iVar3 != (param_2 - 2U & 7) + 0xd0)) {
27: lVar1 = *param_1;
28: *(undefined4 *)(lVar1 + 0x28) = 0x61;
29: *(int *)(lVar1 + 0x2c) = iVar3;
30: *(undefined4 *)(lVar1 + 0x30) = 1;
31: (**(code **)(lVar1 + 8))(param_1,4);
32: *(undefined4 *)((long)param_1 + 0x21c) = 0;
33: return 1;
34: }
35: }
36: lVar1 = *param_1;
37: *(undefined4 *)(lVar1 + 0x28) = 0x61;
38: *(int *)(lVar1 + 0x2c) = iVar3;
39: *(undefined4 *)(lVar1 + 0x30) = 2;
40: (**(code **)(lVar1 + 8))(param_1,4);
41: uVar2 = FUN_00134a80(param_1);
42: if ((int)uVar2 == 0) {
43: return uVar2;
44: }
45: iVar3 = *(int *)((long)param_1 + 0x21c);
46: } while( true );
47: }
48: 
