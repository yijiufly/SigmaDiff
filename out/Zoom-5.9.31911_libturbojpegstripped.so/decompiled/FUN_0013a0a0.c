1: 
2: void FUN_0013a0a0(long param_1)
3: 
4: {
5: long lVar1;
6: uint uVar2;
7: long lVar3;
8: int iVar4;
9: long lVar5;
10: 
11: lVar3 = *(long *)(param_1 + 0x270);
12: lVar1 = (***(code ***)(param_1 + 8))(param_1,1,0x7fc);
13: lVar5 = 0;
14: uVar2 = 0x10;
15: *(long *)(lVar3 + 0x50) = lVar1 + 0x3fc;
16: *(undefined4 *)(lVar1 + 0x3fc) = 0;
17: iVar4 = 0x10;
18: *(undefined4 *)(lVar1 + 0x400) = 1;
19: *(undefined4 *)(lVar1 + 0x3f8) = 0xffffffff;
20: *(undefined4 *)(lVar1 + 0x404) = 2;
21: *(undefined4 *)(lVar1 + 0x3f4) = 0xfffffffe;
22: *(undefined4 *)(lVar1 + 0x408) = 3;
23: *(undefined4 *)(lVar1 + 0x3f0) = 0xfffffffd;
24: *(undefined4 *)(lVar1 + 0x40c) = 4;
25: *(undefined4 *)(lVar1 + 0x3ec) = 0xfffffffc;
26: *(undefined4 *)(lVar1 + 0x410) = 5;
27: *(undefined4 *)(lVar1 + 1000) = 0xfffffffb;
28: *(undefined4 *)(lVar1 + 0x414) = 6;
29: *(undefined4 *)(lVar1 + 0x3e4) = 0xfffffffa;
30: *(undefined4 *)(lVar1 + 0x418) = 7;
31: *(undefined4 *)(lVar1 + 0x3e0) = 0xfffffff9;
32: *(undefined4 *)(lVar1 + 0x41c) = 8;
33: *(undefined4 *)(lVar1 + 0x3dc) = 0xfffffff8;
34: *(undefined4 *)(lVar1 + 0x420) = 9;
35: *(undefined4 *)(lVar1 + 0x3d8) = 0xfffffff7;
36: *(undefined4 *)(lVar1 + 0x424) = 10;
37: *(undefined4 *)(lVar1 + 0x3d4) = 0xfffffff6;
38: *(undefined4 *)(lVar1 + 0x428) = 0xb;
39: *(undefined4 *)(lVar1 + 0x3d0) = 0xfffffff5;
40: *(undefined4 *)(lVar1 + 0x42c) = 0xc;
41: *(undefined4 *)(lVar1 + 0x3cc) = 0xfffffff4;
42: *(undefined4 *)(lVar1 + 0x430) = 0xd;
43: *(undefined4 *)(lVar1 + 0x3c8) = 0xfffffff3;
44: *(undefined4 *)(lVar1 + 0x434) = 0xe;
45: *(undefined4 *)(lVar1 + 0x3c4) = 0xfffffff2;
46: *(undefined4 *)(lVar1 + 0x438) = 0xf;
47: *(undefined4 *)(lVar1 + 0x3c0) = 0xfffffff1;
48: do {
49: uVar2 = uVar2 + 1;
50: *(int *)(lVar1 + 0x43c + lVar5) = iVar4;
51: *(int *)((lVar1 + 0x3bc) - lVar5) = -iVar4;
52: lVar5 = lVar5 + 4;
53: iVar4 = iVar4 + (uVar2 & 1 ^ 1);
54: } while (uVar2 != 0x30);
55: lVar3 = 0;
56: do {
57: *(int *)(lVar1 + 0x4bc + lVar3) = iVar4;
58: lVar5 = lVar3 + 4;
59: *(int *)((lVar1 + 0x33c) - lVar3) = -iVar4;
60: lVar3 = lVar5;
61: } while (lVar5 != 0x340);
62: return;
63: }
64: 
