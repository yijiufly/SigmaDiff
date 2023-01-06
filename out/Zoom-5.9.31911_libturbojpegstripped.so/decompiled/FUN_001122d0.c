1: 
2: void FUN_001122d0(long param_1)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: int iVar6;
11: long lVar7;
12: undefined8 auStack88 [2];
13: undefined8 uStack72;
14: undefined8 uStack64;
15: 
16: iVar6 = 0;
17: lVar1 = *(long *)(param_1 + 0x1f0);
18: auStack88[0] = 0;
19: auStack88[1] = 0;
20: uStack72 = 0;
21: uStack64 = 0;
22: lVar7 = param_1;
23: if (0 < *(int *)(param_1 + 0x144)) {
24: do {
25: lVar5 = (long)*(int *)(*(long *)(lVar7 + 0x148) + 0x14);
26: lVar4 = (long)*(int *)(*(long *)(lVar7 + 0x148) + 0x18);
27: if (*(int *)((long)auStack88 + lVar5 * 4) == 0) {
28: lVar3 = param_1 + lVar5 * 8;
29: lVar2 = *(long *)(lVar3 + 0x80);
30: if (lVar2 == 0) {
31: lVar2 = FUN_00116780(param_1);
32: *(long *)(lVar3 + 0x80) = lVar2;
33: }
34: FUN_00111e20(param_1,lVar2,*(undefined8 *)(lVar1 + 0x80 + lVar5 * 8));
35: *(undefined4 *)((long)auStack88 + lVar5 * 4) = 1;
36: }
37: if (*(int *)((long)auStack88 + lVar4 * 4 + 0x10) == 0) {
38: lVar5 = param_1 + lVar4 * 8;
39: lVar3 = *(long *)(lVar5 + 0xa0);
40: if (lVar3 == 0) {
41: lVar3 = FUN_00116780(param_1);
42: *(long *)(lVar5 + 0xa0) = lVar3;
43: }
44: FUN_00111e20(param_1,lVar3,*(undefined8 *)(lVar1 + 0xa0 + lVar4 * 8));
45: *(undefined4 *)((long)auStack88 + lVar4 * 4 + 0x10) = 1;
46: }
47: iVar6 = iVar6 + 1;
48: lVar7 = lVar7 + 8;
49: } while (*(int *)(param_1 + 0x144) != iVar6 && iVar6 <= *(int *)(param_1 + 0x144));
50: }
51: return;
52: }
53: 
