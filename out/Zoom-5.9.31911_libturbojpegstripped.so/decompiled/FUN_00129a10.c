1: 
2: undefined8 FUN_00129a10(long *param_1)
3: 
4: {
5: long lVar1;
6: byte bVar2;
7: byte bVar3;
8: byte **ppbVar4;
9: long lVar5;
10: int iVar6;
11: byte *pbVar7;
12: byte *pbVar8;
13: 
14: ppbVar4 = (byte **)param_1[5];
15: pbVar7 = ppbVar4[1];
16: pbVar8 = *ppbVar4;
17: if (pbVar7 == (byte *)0x0) {
18: iVar6 = (*(code *)ppbVar4[3])();
19: if (iVar6 == 0) {
20: return 0;
21: }
22: pbVar8 = *ppbVar4;
23: pbVar7 = ppbVar4[1];
24: }
25: bVar2 = *pbVar8;
26: pbVar7 = pbVar7 + -1;
27: if (pbVar7 == (byte *)0x0) {
28: iVar6 = (*(code *)ppbVar4[3])(param_1);
29: if (iVar6 == 0) {
30: return 0;
31: }
32: pbVar8 = *ppbVar4;
33: pbVar7 = ppbVar4[1];
34: }
35: else {
36: pbVar8 = pbVar8 + 1;
37: }
38: bVar3 = *pbVar8;
39: lVar5 = *param_1;
40: *(undefined4 *)(lVar5 + 0x28) = 0x5b;
41: lVar1 = (ulong)bVar2 * 0x100 + -2 + (ulong)bVar3;
42: *(undefined4 *)(lVar5 + 0x2c) = *(undefined4 *)((long)param_1 + 0x21c);
43: *(int *)(*param_1 + 0x30) = (int)lVar1;
44: (**(code **)(*param_1 + 8))(param_1,1);
45: *ppbVar4 = pbVar8 + 1;
46: ppbVar4[1] = pbVar7 + -1;
47: if (0 < lVar1) {
48: (**(code **)(param_1[5] + 0x20))(param_1,lVar1);
49: }
50: return 1;
51: }
52: 
