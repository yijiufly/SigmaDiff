1: 
2: void FUN_0013d740(code **param_1)
3: 
4: {
5: code *pcVar1;
6: int iVar2;
7: code **ppcVar3;
8: char *pcVar4;
9: byte abStack56 [16];
10: code *apcStack40 [3];
11: 
12: param_1[1] = (code *)0x0;
13: apcStack40[0] = (code *)FUN_0013d960();
14: ppcVar3 = (code **)FUN_0013d8e0(param_1,0xa8);
15: if (ppcVar3 == (code **)0x0) {
16: FUN_0013d970(param_1);
17: pcVar1 = *param_1;
18: *(undefined4 *)(pcVar1 + 0x28) = 0x36;
19: *(undefined4 *)(pcVar1 + 0x2c) = 0;
20: (**(code **)*param_1)(param_1);
21: }
22: ppcVar3[0xc] = (code *)0x3b9aca00;
23: ppcVar3[0xe] = (code *)0x0;
24: ppcVar3[0x10] = (code *)0x0;
25: *ppcVar3 = FUN_0013bee0;
26: ppcVar3[0xd] = (code *)0x0;
27: ppcVar3[0xf] = (code *)0x0;
28: ppcVar3[0x11] = (code *)0x0;
29: ppcVar3[1] = FUN_0013c290;
30: ppcVar3[0x12] = (code *)0x0;
31: ppcVar3[0x13] = (code *)0xa8;
32: ppcVar3[2] = FUN_0013cdb0;
33: ppcVar3[3] = FUN_0013cb30;
34: ppcVar3[4] = FUN_0013d540;
35: ppcVar3[5] = FUN_0013d340;
36: ppcVar3[6] = FUN_0013d070;
37: ppcVar3[7] = FUN_0013c7b0;
38: ppcVar3[8] = FUN_0013c410;
39: ppcVar3[9] = FUN_0013c0d0;
40: ppcVar3[10] = FUN_0013c250;
41: ppcVar3[0xb] = apcStack40[0];
42: param_1[1] = (code *)ppcVar3;
43: pcVar4 = getenv("JPEGMEM");
44: if (pcVar4 != (char *)0x0) {
45: abStack56[0] = 0x78;
46: iVar2 = __isoc99_sscanf(pcVar4,"%ld%c",apcStack40,abStack56);
47: if (0 < iVar2) {
48: if ((abStack56[0] & 0xdf) == 0x4d) {
49: apcStack40[0] = (code *)((long)apcStack40[0] * 1000);
50: }
51: ppcVar3[0xb] = (code *)((long)apcStack40[0] * 1000);
52: }
53: }
54: return;
55: }
56: 
