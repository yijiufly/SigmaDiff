1: 
2: void FUN_00125bc0(long *param_1)
3: 
4: {
5: int iVar1;
6: undefined4 uVar2;
7: long lVar3;
8: long lVar4;
9: int iVar5;
10: uint uVar6;
11: long lVar7;
12: bool bVar8;
13: 
14: lVar3 = param_1[0x4a];
15: if (((*(int *)((long)param_1 + 0x20c) != 0) || (param_1[0x42] != 0x3f)) ||
16: (*(int *)(param_1 + 0x43) != 0)) {
17: lVar7 = *param_1;
18: *(undefined4 *)(lVar7 + 0x28) = 0x7a;
19: (**(code **)(lVar7 + 8))(param_1);
20: }
21: lVar7 = 0;
22: if (0 < *(int *)(param_1 + 0x36)) {
23: do {
24: iVar5 = *(int *)(param_1[lVar7 + 0x37] + 0x14);
25: iVar1 = *(int *)(param_1[lVar7 + 0x37] + 0x18);
26: FUN_00125450(param_1,1,iVar5,lVar3 + 0x40 + (long)iVar5 * 8);
27: FUN_00125450(param_1,0,iVar1,lVar3 + 0x60 + (long)iVar1 * 8);
28: *(undefined4 *)(lVar3 + 0x28 + lVar7 * 4) = 0;
29: iVar5 = (int)lVar7 + 1;
30: lVar7 = lVar7 + 1;
31: } while (*(int *)(param_1 + 0x36) != iVar5 && iVar5 <= *(int *)(param_1 + 0x36));
32: }
33: iVar5 = *(int *)(param_1 + 0x3c);
34: lVar7 = 0;
35: if (0 < iVar5) {
36: do {
37: lVar4 = param_1[(long)*(int *)((long)param_1 + lVar7 * 4 + 0x1e4) + 0x37];
38: *(undefined8 *)(lVar3 + 0x80 + lVar7 * 8) =
39: *(undefined8 *)(lVar3 + 0x40 + (long)*(int *)(lVar4 + 0x14) * 8);
40: *(undefined8 *)(lVar3 + 0xd0 + lVar7 * 8) =
41: *(undefined8 *)(lVar3 + 0x60 + (long)*(int *)(lVar4 + 0x18) * 8);
42: bVar8 = *(int *)(lVar4 + 0x30) != 0;
43: if (bVar8) {
44: uVar6 = (uint)(1 < *(int *)(lVar4 + 0x24));
45: }
46: else {
47: uVar6 = 0;
48: }
49: *(uint *)(lVar3 + 0x148 + lVar7 * 4) = uVar6;
50: *(uint *)(lVar3 + 0x120 + lVar7 * 4) = (uint)bVar8;
51: lVar7 = lVar7 + 1;
52: } while ((int)lVar7 < iVar5);
53: }
54: uVar2 = *(undefined4 *)(param_1 + 0x2e);
55: *(undefined4 *)(lVar3 + 0x20) = 0;
56: *(undefined8 *)(lVar3 + 0x18) = 0;
57: *(undefined4 *)(lVar3 + 0x10) = 0;
58: *(undefined4 *)(lVar3 + 0x38) = uVar2;
59: return;
60: }
61: 
