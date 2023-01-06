1: 
2: void FUN_0011f550(code **param_1,uint param_2,long param_3,int param_4,int param_5)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: undefined2 uVar3;
8: code *pcVar4;
9: long lVar5;
10: long lVar6;
11: 
12: iVar1 = *(int *)((long)param_1 + 0x24);
13: if (iVar1 != 100) {
14: ppcVar2 = (code **)*param_1;
15: *(undefined4 *)(ppcVar2 + 5) = 0x14;
16: *(int *)((long)ppcVar2 + 0x2c) = iVar1;
17: (**ppcVar2)();
18: }
19: if (3 < param_2) {
20: ppcVar2 = (code **)*param_1;
21: *(undefined4 *)(ppcVar2 + 5) = 0x1f;
22: *(uint *)((long)ppcVar2 + 0x2c) = param_2;
23: (**ppcVar2)();
24: }
25: pcVar4 = (param_1 + (int)param_2)[0xc];
26: if (pcVar4 == (code *)0x0) {
27: pcVar4 = (code *)FUN_0011f510();
28: (param_1 + (int)param_2)[0xc] = pcVar4;
29: }
30: lVar6 = 0;
31: do {
32: while( true ) {
33: uVar3 = 1;
34: lVar5 = (long)((ulong)*(uint *)(param_3 + lVar6 * 4) * (long)param_4 + 0x32) / 100;
35: if ((lVar5 < 1) || ((0xff < lVar5 && (uVar3 = 0xff, param_5 != 0)))) break;
36: if (0x7fff < lVar5) {
37: lVar5 = 0x7fff;
38: }
39: *(short *)(pcVar4 + lVar6 * 2) = (short)lVar5;
40: lVar6 = lVar6 + 1;
41: if (lVar6 == 0x40) goto LAB_0011f627;
42: }
43: *(undefined2 *)(pcVar4 + lVar6 * 2) = uVar3;
44: lVar6 = lVar6 + 1;
45: } while (lVar6 != 0x40);
46: LAB_0011f627:
47: *(undefined4 *)(pcVar4 + 0x80) = 0;
48: return;
49: }
50: 
