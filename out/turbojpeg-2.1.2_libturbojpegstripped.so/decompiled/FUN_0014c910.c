1: 
2: void FUN_0014c910(code **param_1)
3: 
4: {
5: undefined4 uVar1;
6: code *pcVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: undefined (*pauVar5) [16];
10: int iVar6;
11: ulong uVar7;
12: long lVar8;
13: undefined8 *puVar9;
14: byte bVar10;
15: 
16: bVar10 = 0;
17: pcVar2 = param_1[0x4a];
18: iVar6 = (**(code **)(param_1[0x49] + 0x10))();
19: if (iVar6 == 0) {
20: ppcVar3 = (code **)*param_1;
21: *(undefined4 *)(ppcVar3 + 5) = 0x18;
22: (**ppcVar3)();
23: }
24: if (0 < *(int *)(param_1 + 0x36)) {
25: lVar8 = 1;
26: do {
27: pcVar4 = param_1[lVar8 + 0x36];
28: if (*(int *)(param_1 + 0x27) == 0) {
29: LAB_0014c980:
30: pauVar5 = *(undefined (**) [16])(pcVar2 + (long)*(int *)(pcVar4 + 0x14) * 8 + 0x50);
31: *pauVar5 = (undefined  [16])0x0;
32: pauVar5[1] = (undefined  [16])0x0;
33: pauVar5[2] = (undefined  [16])0x0;
34: pauVar5[3] = (undefined  [16])0x0;
35: *(undefined4 *)(pcVar2 + lVar8 * 4 + 0x28) = 0;
36: *(undefined4 *)(pcVar2 + lVar8 * 4 + 0x38) = 0;
37: if ((*(int *)(param_1 + 0x27) == 0) || (*(int *)((long)param_1 + 0x20c) != 0)) {
38: LAB_0014c9b6:
39: puVar9 = *(undefined8 **)(pcVar2 + (long)*(int *)(pcVar4 + 0x18) * 8 + 0xd0);
40: *puVar9 = 0;
41: puVar9[0x1f] = 0;
42: uVar7 = (ulong)(((int)puVar9 -
43: (int)(undefined8 *)((ulong)(puVar9 + 1) & 0xfffffffffffffff8)) + 0x100U >>
44: 3);
45: puVar9 = (undefined8 *)((ulong)(puVar9 + 1) & 0xfffffffffffffff8);
46: while (uVar7 != 0) {
47: uVar7 = uVar7 - 1;
48: *puVar9 = 0;
49: puVar9 = puVar9 + (ulong)bVar10 * -2 + 1;
50: }
51: }
52: }
53: else {
54: if (*(int *)((long)param_1 + 0x20c) != 0) goto LAB_0014c9b6;
55: if (*(int *)((long)param_1 + 0x214) == 0) goto LAB_0014c980;
56: }
57: iVar6 = (int)lVar8;
58: lVar8 = lVar8 + 1;
59: } while (*(int *)(param_1 + 0x36) != iVar6 && iVar6 <= *(int *)(param_1 + 0x36));
60: }
61: uVar1 = *(undefined4 *)(param_1 + 0x2e);
62: *(undefined8 *)(pcVar2 + 0x18) = 0;
63: *(undefined8 *)(pcVar2 + 0x20) = 0;
64: *(undefined4 *)(pcVar2 + 0x28) = 0xfffffff0;
65: *(undefined4 *)(pcVar2 + 0x4c) = uVar1;
66: return;
67: }
68: 
