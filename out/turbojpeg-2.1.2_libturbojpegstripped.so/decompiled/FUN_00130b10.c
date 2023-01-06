1: 
2: ulong FUN_00130b10(long param_1,ulong param_2,int param_3,long param_4,int param_5)
3: 
4: {
5: long *plVar1;
6: int iVar2;
7: ulong uVar3;
8: long lVar4;
9: 
10: if (param_3 < param_5) {
11: iVar2 = FUN_00130960();
12: if (iVar2 == 0) {
13: return 0xffffffff;
14: }
15: param_2 = *(ulong *)(param_1 + 0x10);
16: param_3 = *(int *)(param_1 + 0x18);
17: }
18: param_3 = param_3 - param_5;
19: uVar3 = SEXT48((int)((1 << ((byte)param_5 & 0x1f)) - 1U &
20: (uint)(param_2 >> ((byte)param_3 & 0x3f))));
21: if (*(long *)(param_4 + (long)param_5 * 8) < (long)uVar3) {
22: lVar4 = (long)(param_5 + 1);
23: do {
24: if (param_3 < 1) {
25: iVar2 = FUN_00130960(param_1);
26: if (iVar2 == 0) {
27: return 0xffffffff;
28: }
29: param_2 = *(ulong *)(param_1 + 0x10);
30: param_3 = *(int *)(param_1 + 0x18);
31: }
32: param_3 = param_3 + -1;
33: param_5 = (int)lVar4;
34: lVar4 = lVar4 + 1;
35: uVar3 = (ulong)((uint)(param_2 >> ((byte)param_3 & 0x3f)) & 1) | uVar3 * 2;
36: } while (*(long *)(param_4 + -8 + lVar4 * 8) < (long)uVar3);
37: }
38: *(ulong *)(param_1 + 0x10) = param_2;
39: *(int *)(param_1 + 0x18) = param_3;
40: if (param_5 < 0x11) {
41: return (ulong)*(byte *)(*(long *)(param_4 + 0x120) + 0x11 +
42: (long)((int)uVar3 + *(int *)(param_4 + 0x90 + (long)param_5 * 8)));
43: }
44: plVar1 = *(long **)(param_1 + 0x20);
45: lVar4 = *plVar1;
46: *(undefined4 *)(lVar4 + 0x28) = 0x76;
47: (**(code **)(lVar4 + 8))(plVar1,0xffffffff);
48: return 0;
49: }
50: 
