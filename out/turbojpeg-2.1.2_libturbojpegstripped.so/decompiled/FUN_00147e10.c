1: 
2: void FUN_00147e10(long param_1,byte **param_2,char **param_3,int param_4,undefined8 param_5,
3: undefined8 param_6)
4: 
5: {
6: byte *pbVar1;
7: byte **ppbVar2;
8: short sVar3;
9: int iVar4;
10: long lVar5;
11: short *psVar6;
12: char *pcVar7;
13: byte *pbVar8;
14: byte *pbVar9;
15: char **ppcStack80;
16: 
17: lVar5 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
18: iVar4 = *(int *)(param_1 + 0x88);
19: if ((0 < param_4) && (iVar4 != 0)) {
20: ppbVar2 = param_2 + (ulong)(param_4 - 1) + 1;
21: ppcStack80 = param_3;
22: do {
23: pbVar1 = *param_2 + (ulong)(iVar4 - 1) * 3 + 3;
24: pcVar7 = *ppcStack80;
25: pbVar8 = *param_2;
26: do {
27: while( true ) {
28: pbVar9 = pbVar8 + 3;
29: psVar6 = (short *)((ulong)(pbVar8[1] >> 2) * 0x40 + (ulong)(pbVar8[2] >> 3) * 2 +
30: *(long *)(lVar5 + (ulong)(*pbVar8 >> 3) * 8));
31: sVar3 = *psVar6;
32: if (sVar3 == 0) break;
33: *pcVar7 = (char)sVar3 + -1;
34: pcVar7 = pcVar7 + 1;
35: pbVar8 = pbVar9;
36: if (pbVar9 == pbVar1) goto LAB_00147ed2;
37: }
38: FUN_001472b0(param_1,*pbVar8 >> 3,pbVar8[1] >> 2,pbVar8[2] >> 3,param_5,param_6,param_1);
39: *pcVar7 = (char)*psVar6 + -1;
40: pcVar7 = pcVar7 + 1;
41: pbVar8 = pbVar9;
42: } while (pbVar9 != pbVar1);
43: LAB_00147ed2:
44: param_2 = param_2 + 1;
45: ppcStack80 = ppcStack80 + 1;
46: } while (ppbVar2 != param_2);
47: }
48: return;
49: }
50: 
