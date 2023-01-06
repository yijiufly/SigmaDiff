1: 
2: undefined8 tjInitDecompress(void)
3: 
4: {
5: void *pvVar1;
6: undefined8 uVar2;
7: undefined4 *puVar3;
8: 
9: pvVar1 = calloc(0x6d8,1);
10: if (pvVar1 != (void *)0x0) {
11: *(undefined *)((long)pvVar1 + 0x610) = 0;
12: *(undefined8 *)((long)pvVar1 + 0x608) = 0x726f727265206f4e;
13: uVar2 = FUN_0014e780(pvVar1);
14: return uVar2;
15: }
16: puVar3 = (undefined4 *)__tls_get_addr(&PTR_00398fc0);
17: *(undefined8 *)(puVar3 + 8) = 0x6166206e6f697461;
18: puVar3[10] = 0x72756c69;
19: *puVar3 = 0x6e496a74;
20: puVar3[1] = 0x65447469;
21: puVar3[2] = 0x706d6f63;
22: puVar3[3] = 0x73736572;
23: *(undefined2 *)(puVar3 + 0xb) = 0x65;
24: puVar3[4] = 0x203a2928;
25: puVar3[5] = 0x6f6d654d;
26: puVar3[6] = 0x61207972;
27: puVar3[7] = 0x636f6c6c;
28: return 0;
29: }
30: 
