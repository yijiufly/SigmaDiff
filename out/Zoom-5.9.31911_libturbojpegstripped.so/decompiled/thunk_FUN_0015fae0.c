1: 
2: void thunk_FUN_0015fae0(undefined (*param_1) [16],float *param_2,float *param_3)
3: 
4: {
5: long lVar1;
6: undefined auVar2 [16];
7: undefined auVar3 [16];
8: 
9: lVar1 = 4;
10: do {
11: auVar2 = packssdw(CONCAT412((int)(param_3[3] * param_2[3]),
12: CONCAT48((int)(param_3[2] * param_2[2]),
13: CONCAT44((int)(param_3[1] * param_2[1]),
14: (int)(*param_3 * *param_2)))),
15: CONCAT412((int)(param_3[7] * param_2[7]),
16: CONCAT48((int)(param_3[6] * param_2[6]),
17: CONCAT44((int)(param_3[5] * param_2[5]),
18: (int)(param_3[4] * param_2[4])))));
19: auVar3 = packssdw(CONCAT412((int)(param_3[0xb] * param_2[0xb]),
20: CONCAT48((int)(param_3[10] * param_2[10]),
21: CONCAT44((int)(param_3[9] * param_2[9]),
22: (int)(param_3[8] * param_2[8])))),
23: CONCAT412((int)(param_3[0xf] * param_2[0xf]),
24: CONCAT48((int)(param_3[0xe] * param_2[0xe]),
25: CONCAT44((int)(param_3[0xd] * param_2[0xd]),
26: (int)(param_3[0xc] * param_2[0xc])))));
27: *param_1 = auVar2;
28: param_1[1] = auVar3;
29: param_3 = param_3 + 0x10;
30: param_2 = param_2 + 0x10;
31: param_1 = param_1[2];
32: lVar1 = lVar1 + -1;
33: } while (lVar1 != 0);
34: return;
35: }
36: 
