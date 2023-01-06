1: 
2: void FUN_0011c140(long param_1,undefined8 param_2,int *param_3,undefined4 param_4)
3: 
4: {
5: long lVar1;
6: uint uVar2;
7: uint uVar3;
8: int iVar4;
9: uint uVar5;
10: 
11: lVar1 = *(long *)(param_1 + 0x1b8);
12: if (*(uint *)(lVar1 + 0x10) < *(uint *)(param_1 + 0x140)) {
13: uVar3 = *(uint *)(lVar1 + 0x14);
14: if (7 < uVar3) goto LAB_0011c1c6;
15: do {
16: while( true ) {
17: (**(code **)(*(long *)(param_1 + 0x1c0) + 8))
18: (param_1,param_2,param_3,param_4,lVar1 + 0x20,lVar1 + 0x14,8);
19: uVar3 = *(uint *)(lVar1 + 0x14);
20: LAB_0011c1c6:
21: if (uVar3 != 8) {
22: return;
23: }
24: iVar4 = (**(code **)(*(long *)(param_1 + 0x1c8) + 8))(param_1,lVar1 + 0x20);
25: if (iVar4 == 0) {
26: if (*(int *)(lVar1 + 0x18) != 0) {
27: return;
28: }
29: *param_3 = *param_3 + -1;
30: *(undefined4 *)(lVar1 + 0x18) = 1;
31: return;
32: }
33: if (*(int *)(lVar1 + 0x18) != 0) break;
34: *(undefined4 *)(lVar1 + 0x14) = 0;
35: uVar5 = *(int *)(lVar1 + 0x10) + 1;
36: uVar3 = *(uint *)(param_1 + 0x140);
37: *(uint *)(lVar1 + 0x10) = uVar5;
38: if (uVar3 <= uVar5) {
39: return;
40: }
41: }
42: *param_3 = *param_3 + 1;
43: *(undefined8 *)(lVar1 + 0x14) = 0;
44: uVar2 = *(int *)(lVar1 + 0x10) + 1;
45: uVar3 = *(uint *)(param_1 + 0x140);
46: uVar5 = *(uint *)(param_1 + 0x140);
47: *(uint *)(lVar1 + 0x10) = uVar2;
48: } while (uVar2 <= uVar3 && uVar5 != uVar2);
49: }
50: return;
51: }
52: 
