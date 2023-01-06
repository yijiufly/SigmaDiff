1: 
2: undefined8 FUN_00134990(long *param_1)
3: 
4: {
5: long lVar1;
6: byte bVar2;
7: byte **ppbVar3;
8: long lVar4;
9: int iVar5;
10: byte *pbVar6;
11: undefined8 uVar7;
12: byte *pbVar8;
13: 
14: ppbVar3 = (byte **)param_1[5];
15: pbVar6 = ppbVar3[1];
16: if (pbVar6 == (byte *)0x0) {
17: iVar5 = (*(code *)ppbVar3[3])();
18: if (iVar5 != 0) {
19: pbVar8 = *ppbVar3;
20: pbVar6 = ppbVar3[1];
21: goto LAB_001349bf;
22: }
23: LAB_00134a50:
24: uVar7 = 0;
25: }
26: else {
27: pbVar8 = *ppbVar3;
28: LAB_001349bf:
29: bVar2 = *pbVar8;
30: pbVar8 = pbVar8 + 1;
31: pbVar6 = pbVar6 + -1;
32: if (pbVar6 == (byte *)0x0) {
33: iVar5 = (*(code *)ppbVar3[3])(param_1);
34: if (iVar5 == 0) goto LAB_00134a50;
35: pbVar8 = *ppbVar3;
36: pbVar6 = ppbVar3[1];
37: }
38: lVar1 = (ulong)bVar2 * 0x100 + -2 + (ulong)*pbVar8;
39: lVar4 = *param_1;
40: *(undefined4 *)(lVar4 + 0x2c) = *(undefined4 *)((long)param_1 + 0x21c);
41: *(undefined4 *)(lVar4 + 0x28) = 0x5b;
42: *(int *)(lVar4 + 0x30) = (int)lVar1;
43: (**(code **)(lVar4 + 8))(param_1,1);
44: *ppbVar3 = pbVar8 + 1;
45: ppbVar3[1] = pbVar6 + -1;
46: if (0 < lVar1) {
47: (**(code **)(param_1[5] + 0x20))(param_1,lVar1);
48: return 1;
49: }
50: uVar7 = 1;
51: }
52: return uVar7;
53: }
54: 
