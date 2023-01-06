1: 
2: void FUN_001127b0(long param_1,undefined8 param_2,int *param_3,undefined4 param_4)
3: 
4: {
5: uint uVar1;
6: uint uVar2;
7: long lVar3;
8: int iVar4;
9: uint uVar5;
10: 
11: lVar3 = *(long *)(param_1 + 0x1b8);
12: if (*(uint *)(lVar3 + 0x10) < *(uint *)(param_1 + 0x140)) {
13: uVar1 = *(uint *)(lVar3 + 0x14);
14: if (uVar1 < 8) goto LAB_00112839;
15: while (uVar1 == 8) {
16: iVar4 = (**(code **)(*(long *)(param_1 + 0x1c8) + 8))(param_1,lVar3 + 0x20);
17: if (iVar4 == 0) {
18: if (*(int *)(lVar3 + 0x18) != 0) {
19: return;
20: }
21: *param_3 = *param_3 + -1;
22: *(undefined4 *)(lVar3 + 0x18) = 1;
23: return;
24: }
25: if (*(int *)(lVar3 + 0x18) != 0) {
26: *param_3 = *param_3 + 1;
27: *(undefined4 *)(lVar3 + 0x18) = 0;
28: }
29: *(undefined4 *)(lVar3 + 0x14) = 0;
30: uVar5 = *(int *)(lVar3 + 0x10) + 1;
31: uVar1 = *(uint *)(param_1 + 0x140);
32: uVar2 = *(uint *)(param_1 + 0x140);
33: *(uint *)(lVar3 + 0x10) = uVar5;
34: if (uVar1 < uVar5 || uVar2 == uVar5) {
35: return;
36: }
37: LAB_00112839:
38: (**(code **)(*(long *)(param_1 + 0x1c0) + 8))
39: (param_1,param_2,param_3,param_4,lVar3 + 0x20,lVar3 + 0x14,8);
40: uVar1 = *(uint *)(lVar3 + 0x14);
41: }
42: }
43: return;
44: }
45: 
