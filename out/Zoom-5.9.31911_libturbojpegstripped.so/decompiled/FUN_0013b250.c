1: 
2: void FUN_0013b250(long param_1,long param_2,long param_3,int param_4)
3: 
4: {
5: byte *pbVar1;
6: byte *pbVar2;
7: short *psVar3;
8: short sVar4;
9: int iVar5;
10: long lVar6;
11: char *pcVar7;
12: byte *pbVar8;
13: long lStack112;
14: 
15: lVar6 = *(long *)(*(long *)(param_1 + 0x270) + 0x30);
16: iVar5 = *(int *)(param_1 + 0x88);
17: if (0 < param_4) {
18: lStack112 = 0;
19: do {
20: pbVar2 = *(byte **)(param_2 + lStack112) + (ulong)(iVar5 - 1) * 3 + 3;
21: pcVar7 = *(char **)(param_3 + lStack112);
22: pbVar8 = *(byte **)(param_2 + lStack112);
23: if (iVar5 != 0) {
24: do {
25: while( true ) {
26: pbVar1 = pbVar8 + 3;
27: psVar3 = (short *)((ulong)(pbVar8[1] >> 2) * 0x40 +
28: *(long *)(lVar6 + (ulong)(*pbVar8 >> 3) * 8) +
29: (ulong)(pbVar8[2] >> 3) * 2);
30: sVar4 = *psVar3;
31: if (sVar4 != 0) break;
32: FUN_0013a910(param_1,*pbVar8 >> 3,pbVar8[1] >> 2,pbVar8[2] >> 3);
33: *pcVar7 = (char)*psVar3 + -1;
34: pcVar7 = pcVar7 + 1;
35: pbVar8 = pbVar1;
36: if (pbVar1 == pbVar2) goto LAB_0013b365;
37: }
38: *pcVar7 = (char)sVar4 + -1;
39: pcVar7 = pcVar7 + 1;
40: pbVar8 = pbVar1;
41: } while (pbVar1 != pbVar2);
42: }
43: LAB_0013b365:
44: lStack112 = lStack112 + 8;
45: } while (lStack112 != (ulong)(param_4 - 1) * 8 + 8);
46: }
47: return;
48: }
49: 
