1: 
2: void FUN_0011bce0(long param_1)
3: 
4: {
5: long lVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long in_FS_OFFSET;
13: undefined auStack104 [16];
14: undefined auStack88 [16];
15: long lStack64;
16: 
17: lVar1 = *(long *)(param_1 + 0x1f0);
18: lStack64 = *(long *)(in_FS_OFFSET + 0x28);
19: auStack104 = (undefined  [16])0x0;
20: auStack88 = (undefined  [16])0x0;
21: if (0 < *(int *)(param_1 + 0x144)) {
22: lVar6 = 1;
23: do {
24: lVar5 = *(long *)(param_1 + 0x140 + lVar6 * 8);
25: lVar7 = (long)*(int *)(lVar5 + 0x14);
26: lVar5 = (long)*(int *)(lVar5 + 0x18);
27: if (*(int *)(auStack104 + lVar7 * 4) == 0) {
28: lVar4 = param_1 + lVar7 * 8;
29: lVar3 = *(long *)(lVar4 + 0x80);
30: if (lVar3 == 0) {
31: lVar3 = FUN_0011f530(param_1);
32: *(long *)(lVar4 + 0x80) = lVar3;
33: }
34: FUN_0011b860(param_1,lVar3,*(undefined8 *)(lVar1 + 0x80 + lVar7 * 8));
35: *(undefined4 *)(auStack104 + lVar7 * 4) = 1;
36: }
37: if (*(int *)(auStack88 + lVar5 * 4) == 0) {
38: lVar7 = param_1 + lVar5 * 8;
39: lVar4 = *(long *)(lVar7 + 0xa0);
40: if (lVar4 == 0) {
41: lVar4 = FUN_0011f530(param_1);
42: *(long *)(lVar7 + 0xa0) = lVar4;
43: }
44: FUN_0011b860(param_1,lVar4,*(undefined8 *)(lVar1 + 0xa0 + lVar5 * 8));
45: *(undefined4 *)(auStack88 + lVar5 * 4) = 1;
46: }
47: iVar2 = (int)lVar6;
48: lVar6 = lVar6 + 1;
49: } while (*(int *)(param_1 + 0x144) != iVar2 && iVar2 <= *(int *)(param_1 + 0x144));
50: }
51: if (lStack64 == *(long *)(in_FS_OFFSET + 0x28)) {
52: return;
53: }
54: /* WARNING: Subroutine does not return */
55: __stack_chk_fail();
56: }
57: 
