1: 
2: undefined8 tjInitTransform(void)
3: 
4: {
5: void *pvVar1;
6: long lVar2;
7: undefined8 uVar3;
8: undefined4 *puVar4;
9: 
10: pvVar1 = calloc(0x6d8,1);
11: if (pvVar1 == (void *)0x0) {
12: puVar4 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
13: *(undefined8 *)(puVar4 + 8) = 0x696166206e6f6974;
14: puVar4[10] = 0x6572756c;
15: *puVar4 = 0x6e496a74;
16: puVar4[1] = 0x72547469;
17: puVar4[2] = 0x66736e61;
18: puVar4[3] = 0x286d726f;
19: *(undefined *)(puVar4 + 0xb) = 0;
20: puVar4[4] = 0x4d203a29;
21: puVar4[5] = 0x726f6d65;
22: puVar4[6] = 0x6c612079;
23: puVar4[7] = 0x61636f6c;
24: }
25: else {
26: *(undefined8 *)((long)pvVar1 + 0x608) = 0x726f727265206f4e;
27: *(undefined *)((long)pvVar1 + 0x610) = 0;
28: lVar2 = FUN_0014e2d0(pvVar1);
29: if (lVar2 != 0) {
30: uVar3 = FUN_0014e780(pvVar1);
31: return uVar3;
32: }
33: }
34: return 0;
35: }
36: 
