# from https://raw.githubusercontent.com/Ko-/aes-armcortexm/public/aes256ctr/aes_256_ctr.s
# taken feb 25/2021
#
.syntax unified
.thumb

.align 2
.type AES_Te0,%object
AES_Te0:
.word 0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b
.word 0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5
.word 0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b
.word 0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76
.word 0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d
.word 0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0
.word 0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf
.word 0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0
.word 0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26
.word 0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc
.word 0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1
.word 0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15
.word 0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3
.word 0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a
.word 0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2
.word 0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75
.word 0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a
.word 0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0
.word 0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3
.word 0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784
.word 0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced
.word 0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b
.word 0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39
.word 0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf
.word 0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb
.word 0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485
.word 0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f
.word 0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8
.word 0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f
.word 0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5
.word 0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321
.word 0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2
.word 0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec
.word 0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917
.word 0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d
.word 0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573
.word 0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc
.word 0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388
.word 0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14
.word 0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db
.word 0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a
.word 0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c
.word 0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662
.word 0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79
.word 0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d
.word 0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9
.word 0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea
.word 0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808
.word 0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e
.word 0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6
.word 0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f
.word 0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a
.word 0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66
.word 0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e
.word 0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9
.word 0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e
.word 0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311
.word 0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794
.word 0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9
.word 0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf
.word 0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d
.word 0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868
.word 0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f
.word 0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16

@ void AES_256_keyschedule(const uint8_t *key,
@       uint8_t *rk) {
.global AES_256_keyschedule
.type   AES_256_keyschedule,%function
AES_256_keyschedule:

    //function prologue, preserve registers
    push {r4-r11,r14}

    //load key
    ldm r0, {r2-r9}

    //load table address once
    adr r0, AES_Te0

    //round 1
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000001 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[8]
    eor r3, r2 //rk[9]
    eor r4, r3 //rk[10]
    eor r5, r4 //rk[11]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[12]
    eor r7, r6 //rk[13]
    eor r8, r7 //rk[14]
    eor r9, r8 //rk[15]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #0]
    str r3, [r1, #4]
    str r4, [r1, #8]
    str r5, [r1, #12]
    str r6, [r1, #16]
    str r7, [r1, #20]
    str r8, [r1, #24]
    str r9, [r1, #28]

    //round 2
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000002 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[16]
    eor r3, r2 //rk[17]
    eor r4, r3 //rk[18]
    eor r5, r4 //rk[19]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[20]
    eor r7, r6 //rk[21]
    eor r8, r7 //rk[22]
    eor r9, r8 //rk[23]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #32]
    str r3, [r1, #36]
    str r4, [r1, #40]
    str r5, [r1, #44]
    str r6, [r1, #48]
    str r7, [r1, #52]
    str r8, [r1, #56]
    str r9, [r1, #60]

    //round 3
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000004 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[24]
    eor r3, r2 //rk[25]
    eor r4, r3 //rk[26]
    eor r5, r4 //rk[27]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[28]
    eor r7, r6 //rk[29]
    eor r8, r7 //rk[30]
    eor r9, r8 //rk[31]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #64]
    str r3, [r1, #68]
    str r4, [r1, #72]
    str r5, [r1, #76]
    str r6, [r1, #80]
    str r7, [r1, #84]
    str r8, [r1, #88]
    str r9, [r1, #92]

    //round 4
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000008 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[32]
    eor r3, r2 //rk[33]
    eor r4, r3 //rk[34]
    eor r5, r4 //rk[35]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[36]
    eor r7, r6 //rk[37]
    eor r8, r7 //rk[38]
    eor r9, r8 //rk[39]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #96]
    str r3, [r1, #100]
    str r4, [r1, #104]
    str r5, [r1, #108]
    str r6, [r1, #112]
    str r7, [r1, #116]
    str r8, [r1, #120]
    str r9, [r1, #124]

    add r1, #128

    //round 5
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000010 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[40]
    eor r3, r2 //rk[41]
    eor r4, r3 //rk[42]
    eor r5, r4 //rk[43]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[44]
    eor r7, r6 //rk[45]
    eor r8, r7 //rk[46]
    eor r9, r8 //rk[47]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #0]
    str r3, [r1, #4]
    str r4, [r1, #8]
    str r5, [r1, #12]
    str r6, [r1, #16]
    str r7, [r1, #20]
    str r8, [r1, #24]
    str r9, [r1, #28]

    //round 6
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000020 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[48]
    eor r3, r2 //rk[49]
    eor r4, r3 //rk[50]
    eor r5, r4 //rk[51]

    uxtb r10, r5, ror #16
    uxtb r11, r5, ror #8
    uxtb r12, r5
    uxtb r14, r5, ror #24

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r6, r6, r10, lsl #16
    eor r6, r6, r11, lsl #8
    eor r6, r12
    eor r6, r6, r14, lsl #24 //rk[52]
    eor r7, r6 //rk[53]
    eor r8, r7 //rk[54]
    eor r9, r8 //rk[55]

    //write to memory
    //stmia.w r1!, {r2-r9} is slower if we can use encoding T1!
    str r2, [r1, #32]
    str r3, [r1, #36]
    str r4, [r1, #40]
    str r5, [r1, #44]
    str r6, [r1, #48]
    str r7, [r1, #52]
    str r8, [r1, #56]
    str r9, [r1, #60]

    //round 7
    uxtb r10, r9, ror #8
    uxtb r11, r9, ror #16
    uxtb r12, r9, ror #24
    uxtb r14, r9

    ldrb r10, [r0, r10, lsl #2]
    ldrb r11, [r0, r11, lsl #2]
    ldrb r12, [r0, r12, lsl #2]
    ldrb r14, [r0, r14, lsl #2]

    eor r2, #0x00000040 //rcon
    eor r2, r2, r10
    eor r2, r2, r11, lsl #8
    eor r2, r2, r12, lsl #16
    eor r2, r2, r14, lsl #24 //rk[56]
    eor r3, r2 //rk[57]
    eor r4, r3 //rk[58]
    eor r5, r4 //rk[59]

    //write to memory
    //stmia.w r1!, {r2-r5} is slower if we can use encoding T1!
    str r2, [r1, #64]
    str r3, [r1, #68]
    str r4, [r1, #72]
    str r5, [r1, #76]

    //function epilogue, restore state
    pop {r4-r11,r14}
    bx lr


.align 2
@ void AES_256_encrypt_ctr(param const *p,
@       const uint8_t *in, uint8_t *out,
@       uint32_t len) {
.global AES_256_encrypt_ctr
.type   AES_256_encrypt_ctr,%function
AES_256_encrypt_ctr:

    //function prologue, preserve registers
    push {r1-r11,r14}

    mov.w r14, r0

    //load table address once
    adr r12, AES_Te0

    //do counter-mode caching precomputation
.align 2
partial_precompute: //expect p in r14

    //load from p ctrnonce in r4-r7, key in r8-r11
    ldmia r14!, {r4-r11}

    //initial addroundkey
    eor r4, r8
    eor r5, r9
    eor r6, r10
    eor r7, r11
    and r4, r4, #0xffffff00

    //round 1

    ldmia r14!, {r8-r11} //rk[4]-rk[7]
    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r4, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r4, [r12, r4, lsl #2]
    ldr r3, [r12, #0] //keep this value here throughout round 2 to save loads
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r4, ror #24
    eor r1, r8, r3, ror #16
    push.w {r1}

    //round 2

    ldmia r14!, {r4-r7} //rk[8]-rk[11]

    uxtb r0, r9
    uxtb r1, r10
    uxtb r2, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r4, r3, ror #16
    eor r5, r5, r0, ror #16
    eor r6, r6, r1, ror #16
    eor r7, r7, r2, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r3
    eor r7, r2

    uxtb r0, r11, ror #24
    uxtb r1, r9, ror #24
    uxtb r2, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r3, ror #24
    eor r6, r6, r1, ror #24
    eor r7, r7, r2, ror #24

    eor r4, r4, r3, ror #16
    eor r5, r5, r3, ror #24
    eor r6, r3
    eor r7, r7, r3, ror #8
    push.w {r4-r7}
    //load precomputed_x0
    ldr r10, [sp, #16]
    //the first time, we can skip some loads
    b.w encrypt_first

    //do full AES on one block using precomputated values
.align 2
encrypt_block: //expect {precomputed_x0, precomputed_y0..y3} on top of stack, p+4*4*4 in r14

    //load precomputed
    ldm sp, {r4-r7,r10}
encrypt_first:
    //load ctr
    ldr r8, [r14, #-64]
    //load key[0]
    ldr r9, [r14, #-48]

    //round 1
    eor r8, r9
    and r8, #0xff
    ldr r8, [r12, r8, lsl #2]
    eor r10, r10, r8, ror #16

    //round 2
    uxtb r0, r10
    uxtb r1, r10, ror #24
    uxtb r2, r10, ror #16
    uxtb r3, r10, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #24
    eor r6, r6, r2
    eor r7, r7, r3, ror #8

    //round 3

    ldmia r14!, {r8-r11} //rk[64]-rk[12]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 4

    ldmia r14!, {r4-r7} //rk[80]-rk[16]

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #16
    eor r6, r6, r2, ror #16
    eor r7, r7, r3, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r1, ror #24
    eor r6, r6, r2, ror #24
    eor r7, r7, r3, ror #24

    //round 5

    ldmia r14!, {r8-r11} //rk[96]-rk[20]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 6

    ldmia r14!, {r4-r7} //rk[112]-rk[24]

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #16
    eor r6, r6, r2, ror #16
    eor r7, r7, r3, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r1, ror #24
    eor r6, r6, r2, ror #24
    eor r7, r7, r3, ror #24

    //round 7

    ldmia r14!, {r8-r11} //rk[128]-rk[28]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 8

    ldmia r14!, {r4-r7} //rk[144]-rk[32]

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #16
    eor r6, r6, r2, ror #16
    eor r7, r7, r3, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r1, ror #24
    eor r6, r6, r2, ror #24
    eor r7, r7, r3, ror #24

    //round 9

    ldmia r14!, {r8-r11} //rk[160]-rk[36]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 10

    ldmia r14!, {r4-r7} //rk[176]-rk[40]

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #16
    eor r6, r6, r2, ror #16
    eor r7, r7, r3, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r1, ror #24
    eor r6, r6, r2, ror #24
    eor r7, r7, r3, ror #24

    //round 11

    ldmia r14!, {r8-r11} //rk[192]-rk[44]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 12

    ldmia r14!, {r4-r7} //rk[208]-rk[48]

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #16
    eor r6, r6, r2, ror #16
    eor r7, r7, r3, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #24
    eor r5, r5, r1, ror #24
    eor r6, r6, r2, ror #24
    eor r7, r7, r3, ror #24

    //round 13

    ldmia r14!, {r8-r11} //rk[224]-rk[52]

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r3, ror #24

    //round 14

    uxtb r0, r8
    uxtb r1, r9
    uxtb r2, r10
    uxtb r3, r11
    ldr r4, [r12, r0, lsl #2]
    ldr r5, [r12, r1, lsl #2]
    ldr r6, [r12, r2, lsl #2]
    ldr r7, [r12, r3, lsl #2]

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    uxtb r2, r8, ror #16
    uxtb r3, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    bfi r4, r0, #16, #8
    bfi r5, r1, #16, #8
    bfi r6, r2, #16, #8
    bfi r7, r3, #16, #8

    uxtb r0, r11, ror #24
    uxtb r1, r8, ror #24
    uxtb r2, r9, ror #24
    uxtb r3, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    bfi r4, r0, #24, #8
    bfi r5, r1, #24, #8
    bfi r6, r2, #24, #8
    bfi r7, r3, #24, #8

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    uxtb r3, r8, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    bfi r4, r0, #8, #8
    bfi r5, r1, #8, #8
    bfi r6, r2, #8, #8
    bfi r7, r3, #8, #8

    ldmia r14!, {r0-r3} //rk[56]-rk[59]

    eor r4, r0
    eor r5, r1
    eor r6, r2
    eor r7, r3


    //load in, out, len counter
    add r8, sp, #20 //step over precomputed_*
    ldmia r8, {r1-r3}

    //load input, xor keystream and write to output
    ldmia r1!, {r8-r11}
    str.w r1, [sp, #20]
    eor r4, r8
    eor r5, r9
    eor r6, r10
    eor r7, r11
    stmia r2!, {r4-r7}
    str r2, [sp, #24]

    //dec and store len counter
    subs r3, #16
    ble exit //if len<=0: exit
    str.w r3, [sp, #28]

    //load, inc, store ctrnonce
    sub r14, #192 //reset to p+4*4*4, as required by encrypt_block
    ldr r4, [r14, #-64]
    add r4, #1
    str r4, [r14, #-64]

    //if ctrnonce%256==0: partial_precompute
    ands r4, r4, #0xff
    bne encrypt_block
    add.w sp, #20 //remove precomputed_*
    sub r14, #64 //reset to p, as required by partial_precompute
    b partial_precompute

.align 2
exit:
    //function epilogue, restore state
    add sp, #32
    pop {r4-r11,r14}
    bx lr

