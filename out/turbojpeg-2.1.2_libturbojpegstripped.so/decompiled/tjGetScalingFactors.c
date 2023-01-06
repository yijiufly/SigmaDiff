1: 
2: undefined * tjGetScalingFactors(undefined4 *param_1)
3: 
4: {
5: undefined4 *puVar1;
6: 
7: if (param_1 != (undefined4 *)0x0) {
8: *param_1 = 0x10;
9: return &DAT_0018fcc0;
10: }
11: puVar1 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
12: *(undefined8 *)(puVar1 + 8) = 0x746e656d756772;
13: *puVar1 = 0x65476a74;
14: puVar1[1] = 0x61635374;
15: puVar1[2] = 0x676e696c;
16: puVar1[3] = 0x74636146;
17: puVar1[4] = 0x2873726f;
18: puVar1[5] = 0x49203a29;
19: puVar1[6] = 0x6c61766e;
20: puVar1[7] = 0x61206469;
21: return (undefined *)0x0;
22: }
23: 
