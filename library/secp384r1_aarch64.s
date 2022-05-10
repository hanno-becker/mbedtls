
.macro mul_high_x6 a0, a1, a2, a3, a4, a5, b, d0, d1, d2, d3, d4, d5
        umulh \d0, \b, \a0
        umulh \d1, \b, \a1
        umulh \d2, \b, \a2
        umulh \d3, \b, \a3
        umulh \d4, \b, \a4
        umulh \d5, \b, \a5
.endm

.macro mul_low_x6 a0, a1, a2, a3, a4, a5, b, d0, d1, d2, d3, d4, d5
        mul \d0, \b, \a0
        mul \d1, \b, \a1
        mul \d2, \b, \a2
        mul \d3, \b, \a3
        mul \d4, \b, \a4
        mul \d5, \b, \a5
.endm

.macro add_x6 d0, d1, d2, d3, d4, d5, a0, a1, a2, a3, a4, a5
        adds   \d0, \d0, \a0
        adcs   \d1, \d1, \a1
        adcs   \d2, \d2, \a2
        adcs   \d3, \d3, \a3
        adcs   \d4, \d4, \a4
        adc    \d5, \d5, \a5
.endm

.macro sub_x6 d0, d1, d2, d3, d4, d5, a0, a1, a2, a3, a4, a5, borrow
        subs   \d0, \d0, \a0
        sbcs   \d1, \d1, \a1
        sbcs   \d2, \d2, \a2
        sbcs   \d3, \d3, \a3
        sbcs   \d4, \d4, \a4
        sbcs   \d5, \d5, \a5
        cset   \borrow, cc
.endm

.macro add_x6_ext d0, d1, d2, d3, d4, d5, d6, a0, a1, a2, a3, a4, a5
        adds   \d0, \d0, \a0
        adcs   \d1, \d1, \a1
        adcs   \d2, \d2, \a2
        adcs   \d3, \d3, \a3
        adcs   \d4, \d4, \a4
        adcs   \d5, \d5, \a5
        adc    \d6, xzr, xzr
.endm

.macro add_x6_ext2 d0, d1, d2, d3, d4, d5, d6, a0, a1, a2, a3, a4, a5
        adds   \d0, \d0, \a0
        adcs   \d1, \d1, \a1
        adcs   \d2, \d2, \a2
        adcs   \d3, \d3, \a3
        adcs   \d4, \d4, \a4
        adcs   \d5, \d5, \a5
        adc    \d6, \d6, xzr
.endm

.macro add_x6_ext3 d0, d1, d2, d3, d4, d5, d6, d7, a0, a1, a2, a3, a4, a5
        adds   \d0, \d0, \a0
        adcs   \d1, \d1, \a1
        adcs   \d2, \d2, \a2
        adcs   \d3, \d3, \a3
        adcs   \d4, \d4, \a4
        adcs   \d5, \d5, \a5
        adcs   \d6, \d6, xzr
        adc    \d7, \d7, xzr
.endm

.macro cond_sub d0, d1, d2, d3, d4, d5, a0, a1, a2, a3, a4, a5, carry, borrow, t0, t1, t2, t3, t4, t5
        subs   \t0, \d0, \a0
        sbcs   \t1, \d1, \a1
        sbcs   \t2, \d2, \a2
        sbcs   \t3, \d3, \a3
        sbcs   \t4, \d4, \a4
        sbcs   \t5, \d5, \a5
        cset   \borrow, cc
        cmp    \carry, \borrow
        csel   \d0, \d0, \t0, lt
        csel   \d1, \d1, \t1, lt
        csel   \d2, \d2, \t2, lt
        csel   \d3, \d3, \t3, lt
        csel   \d4, \d4, \t4, lt
        csel   \d5, \d5, \t5, lt

        /* Alternative : subtract + conditional add */
        // sub_x6 \d0, \d1, \d2, \d3, \d4, \d5, \a0, \a1, \a2, \a3, \a4, \a5, \borrow
        // cmp \carry, \borrow
        // cset \carry, lt
        // mul \a0, \a0, carry
        // mul \a1, \a1, carry
        // mul \a2, \a2, carry
        // mul \a3, \a3, carry
        // mul \a4, \a4, carry
        // mul \a5, \a5, carry
        // add_x6 \d0, \d1, \d2, \d3, \d4, \d5, \a0, \a1, \a2, \a3, \a4, \a5
.endm

.macro cond_add d0, d1, d2, d3, d4, d5, a0, a1, a2, a3, a4, a5, cond, t0, t1, t2, t3, t4, t5
        adds   \t0, \d0, \a0
        adcs   \t1, \d1, \a1
        adcs   \t2, \d2, \a2
        adcs   \t3, \d3, \a3
        adcs   \t4, \d4, \a4
        adc    \t5, \d5, \a5
        cmp    \cond, #0
        csel   \d0, \d0, \t0, eq
        csel   \d1, \d1, \t1, eq
        csel   \d2, \d2, \t2, eq
        csel   \d3, \d3, \t3, eq
        csel   \d4, \d4, \t4, eq
        csel   \d5, \d5, \t5, eq
.endm

.macro save_gprs
    sub sp, sp, #12*8
    stp x19, x20, [sp, #(16*0)]
    stp x21, x22, [sp, #(16*1)]
    stp x23, x24, [sp, #(16*2)]
    stp x25, x26, [sp, #(16*3)]
    stp x27, x28, [sp, #(16*4)]
    stp x29, x30, [sp, #(16*5)]
.endm

.macro restore_gprs
    ldp x19, x20, [sp, #(16*0)]
    ldp x21, x22, [sp, #(16*1)]
    ldp x23, x24, [sp, #(16*2)]
    ldp x25, x26, [sp, #(16*3)]
    ldp x27, x28, [sp, #(16*4)]
    ldp x29, x30, [sp, #(16*5)]
    add sp, sp, #12*8
.endm

.macro mul_with_low_mod c, m0, m1, t0, t1, t2, t3, tmp0, tmp1
        mul    \t0,    \c, \m0
        umulh  \t1,    \c, \m0
        mul    \tmp0,  \c, \m1
        umulh  \tmp1,  \c, \m1
        adds   \t1,   \t1, \tmp0
        adcs   \t2, \tmp1, \c /* m2 == 1 */
        adc    \t3,   xzr, xzr
.endm

.macro sub_x4_x8 d0, d1, d2, d3, d4, d5, d6, d7, a0, a1, a2, a3
        subs   \d0, \d0, \a0
        sbcs   \d1, \d1, \a1
        sbcs   \d2, \d2, \a2
        sbcs   \d3, \d3, \a3
        sbcs   \d4, \d4, xzr
        sbcs   \d5, \d5, xzr
        sbcs   \d6, \d6, xzr
        sbc    \d7, \d7, xzr
.endm

.macro add_x1_x2 d0, d1, a0
        adds   \d0, \d0, \a0
        adc    \d1, \d1, xzr
.endm

.macro montgomery_fixup X_0, X_1, X_2, X_3, X_4, X_5, X_6, X_7, X_t, T_0, T_1, T_2, T_3, T_4, T_5
        mul_with_low_mod \X_t, M_0, M_1, \T_0, \T_1, \T_2, \T_3, \T_4, \T_5
        add_x1_x2        \X_6, \X_7, \X_t
        sub_x4_x8        \X_0, \X_1, \X_2, \X_3, \X_4, \X_5, \X_6, \X_7, \T_0, \T_1, \T_2, \T_3
.endm

.text
.type mul_384_384, %function
.global mul_384_384
mul_384_384:
        inA .req x1
        inB .req x2
        dst .req x0

        X_0  .req x3
        X_1  .req x4
        X_2  .req x5
        X_3  .req x6
        X_4  .req x7
        X_5  .req x8
        X_6  .req x9
        X_7  .req x10
        X_8  .req x11
        X_9  .req x12
        X_10 .req x13
        X_11 .req x14

        A_0  .req x15
        A_1  .req x16
        A_2  .req x17
        A_3  .req x18
        A_4  .req x19
        A_5  .req x20

        T_0  .req x21
        T_1  .req x22
        T_2  .req x23
        T_3  .req x24
        T_4  .req x25
        T_5  .req x26

        curB .req x27

        save_gprs

        ldp A_0, A_1, [inA, #0*8]
        ldp A_2, A_3, [inA, #2*8]
        ldp A_4, A_5, [inA, #4*8]

        mov X_6, xzr
        ldr curB, [inB, #0*8]
        /* X += A * B[0] */
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  X_0, X_1, X_2, X_3, X_4, X_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_1, X_2, X_3, X_4, X_5, X_6,             T_0, T_1, T_2, T_3, T_4, T_5
        /* X += A * B[1] */
        ldr curB, [inB, #1*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_1, X_2, X_3, X_4, X_5, X_6, X_7,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_2, X_3, X_4, X_5, X_6, X_7              T_0, T_1, T_2, T_3, T_4, T_5
        /* X += A * B[2] */
        ldr curB, [inB, #2*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_2, X_3, X_4, X_5, X_6, X_7, X_8,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_3, X_4, X_5, X_6, X_7, X_8              T_0, T_1, T_2, T_3, T_4, T_5
        /* X += A * B[3] */
        ldr curB, [inB, #3*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,       curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_3, X_4, X_5, X_6, X_7, X_8, X_9,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,       curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_4, X_5, X_6, X_7, X_8, X_9               T_0, T_1, T_2, T_3, T_4, T_5
        /* X += A * B[4] */
        ldr curB, [inB,#4*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,        curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_4, X_5, X_6, X_7, X_8, X_9, X_10,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,        curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_5, X_6, X_7, X_8, X_9, X_10               T_0, T_1, T_2, T_3, T_4, T_5
        /* X += A * B[5] */
        ldr curB, [inB,#5*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,       curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_5, X_6, X_7, X_8, X_9, X_10, X_11,       T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,       curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_6, X_7, X_8, X_9, X_10, X_11,            T_0, T_1, T_2, T_3, T_4, T_5

        stp X_0, X_1,   [dst, #0*8]
        stp X_2, X_3,   [dst, #2*8]
        stp X_4, X_5,   [dst, #4*8]
        stp X_6, X_7,   [dst, #6*8]
        stp X_8, X_9,   [dst, #8*8]
        stp X_10, X_11, [dst, #10*8]

        restore_gprs

        ret

        .unreq inA
        .unreq inB
        .unreq dst

        .unreq X_0
        .unreq X_1
        .unreq X_2
        .unreq X_3
        .unreq X_4
        .unreq X_5
        .unreq X_6
        .unreq X_7
        .unreq X_8
        .unreq X_9
        .unreq X_10
        .unreq X_11

        .unreq A_0
        .unreq A_1
        .unreq A_2
        .unreq A_3
        .unreq A_4
        .unreq A_5

        .unreq T_0
        .unreq T_1
        .unreq T_2
        .unreq T_3
        .unreq T_4
        .unreq T_5

        .unreq curB


        ///////////////////////////////////////////////////////////////////////

.type addmod_384, %function
.global addmod_384
addmod_384:
        inA   .req x1
        inB   .req x2
        mod   .req x3
        dst   .req x0

        curA  .req x4
        curB  .req x5

        borrow .req curA
        carry  .req curB
        fixup  .req mod

        M_0  .req x6
        M_1  .req x7
        M_2  .req x8
        M_3  .req x9
        M_4  .req x10
        M_5  .req x11

        D_0  .req x12
        D_1  .req x13
        D_2  .req x14
        D_3  .req x15
        D_4  .req x16
        D_5  .req x17

        ldr curA, [inA, #0*8]
        ldr curB, [inB, #0*8]
        adds D_0, curA, curB

        ldr curA, [inA, #1*8]
        ldr curB, [inB, #1*8]
        adcs D_1, curA, curB

        ldr curA, [inA, #2*8]
        ldr curB, [inB, #2*8]
        adcs D_2, curA, curB

        ldr curA, [inA, #3*8]
        ldr curB, [inB, #3*8]
        adcs D_3, curA, curB

        ldr curA, [inA, #4*8]
        ldr curB, [inB, #4*8]
        adcs D_4, curA, curB

        ldr curA, [inA, #5*8]
        ldr curB, [inB, #5*8]
        adcs D_5, curA, curB

        adc carry, xzr, xzr

        ldp M_0, M_1, [mod, #0*8]
        ldp M_2, M_3, [mod, #2*8]
        ldp M_4, M_5, [mod, #4*8]

        cond_sub D_0, D_1, D_2, D_3, D_4, D_5, \
                 M_0, M_1, M_2, M_3, M_4, M_5, \
                 carry, borrow,                \
                 M_0, M_1, M_2, M_3, M_4, M_5

        stp D_0, D_1, [dst, #0*8]
        stp D_2, D_3, [dst, #2*8]
        stp D_4, D_5, [dst, #4*8]

        ret

        .unreq inA
        .unreq inB
        .unreq mod
        .unreq dst
        .unreq curA
        .unreq curB
        .unreq borrow
        .unreq carry
        .unreq fixup
        .unreq M_0
        .unreq M_1
        .unreq M_2
        .unreq M_3
        .unreq M_4
        .unreq M_5
        .unreq D_0
        .unreq D_1
        .unreq D_2
        .unreq D_3
        .unreq D_4
        .unreq D_5

        ///////////////////////////////////////////////////////////////////////////////////////////////

.type submod_384, %function
.global submod_384
submod_384:
        inA   .req x1
        inB   .req x2
        mod   .req x3
        dst   .req x0

        curA  .req x4
        curB  .req x5

        borrow .req curA

        M_0  .req x6
        M_1  .req x7
        M_2  .req x8
        M_3  .req x9
        M_4  .req x10
        M_5  .req x11

        D_0  .req x12
        D_1  .req x13
        D_2  .req x14
        D_3  .req x15
        D_4  .req x16
        D_5  .req x17

        ldr curA, [inA, #0*8]
        ldr curB, [inB, #0*8]
        subs D_0, curA, curB

        ldr curA, [inA, #1*8]
        ldr curB, [inB, #1*8]
        sbcs D_1, curA, curB

        ldr curA, [inA, #2*8]
        ldr curB, [inB, #2*8]
        sbcs D_2, curA, curB

        ldr curA, [inA, #3*8]
        ldr curB, [inB, #3*8]
        sbcs D_3, curA, curB

        ldr curA, [inA, #4*8]
        ldr curB, [inB, #4*8]
        sbcs D_4, curA, curB

        ldr curA, [inA, #5*8]
        ldr curB, [inB, #5*8]
        sbcs D_5, curA, curB

        cset borrow, cc

        ldp M_0, M_1, [mod, #0*8]
        ldp M_2, M_3, [mod, #2*8]
        ldp M_4, M_5, [mod, #4*8]

        cond_add D_0, D_1, D_2, D_3, D_4, D_5, \
                 M_0, M_1, M_2, M_3, M_4, M_5, \
                 borrow,                       \
                 M_0, M_1, M_2, M_3, M_4, M_5

        stp D_0, D_1, [dst, #0*8]
        stp D_2, D_3, [dst, #2*8]
        stp D_4, D_5, [dst, #4*8]

        ret

        .unreq inA
        .unreq inB
        .unreq mod
        .unreq dst
        .unreq curA
        .unreq curB
        .unreq borrow
        .unreq M_0
        .unreq M_1
        .unreq M_2
        .unreq M_3
        .unreq M_4
        .unreq M_5
        .unreq D_0
        .unreq D_1
        .unreq D_2
        .unreq D_3
        .unreq D_4
        .unreq D_5


        ///////////////////////////////////////////////////////////////////////////////////////////////

.type montmul_p384, %function
.global montmul_p384
montmul_p384:
        inA   .req x1
        inB   .req x2
        mod   .req x3
        twist .req x4
        dst   .req x0

        X_0  .req x1
        X_1  .req x30
        X_2  .req x5
        X_3  .req x6
        X_4  .req x7
        X_5  .req x8
        X_6  .req x9
        X_7  .req x10

        A_0  .req x11
        A_1  .req x12
        A_2  .req x13
        A_3  .req x14
        A_4  .req x15
        A_5  .req x16

        M_0  .req x17
        M_1  .req x18
        M_2  .req x19
        M_3  .req x20
        M_4  .req x21
        M_5  .req x22

        T_0  .req x23
        T_1  .req x24
        T_2  .req x25
        T_3  .req x26
        T_4  .req x27
        T_5  .req x28

        curB .req x29
        X_t  .req curB

        sub sp, sp, #12*8
        stp x19, x20, [sp, #(16*0)]
        stp x21, x22, [sp, #(16*1)]
        stp x29, x30, [sp, #(16*5)]

        ldp A_0, A_1, [inA, #0*8]
        ldp A_2, A_3, [inA, #2*8]
        ldp A_4, A_5, [inA, #4*8]

        mov  M_0, #0xFFFFFFFF00000001
        mov  M_1, 0x000000000FFFFFFFF

        .unreq inA

        mov X_6, xzr
        mov X_7, xzr

        /* X = A * B[0] */
        ldr curB, [inB, #0*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  X_0, X_1, X_2, X_3, X_4, X_5

        stp T_0, T_1, [sp, #(16*2)]
        stp T_2, T_3, [sp, #(16*3)]
        stp T_4, T_5, [sp, #(16*4)]

        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_1, X_2, X_3, X_4, X_5, X_6,             T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_0, twist
        montgomery_fixup X_0, X_1, X_2, X_3, X_4, X_5, X_6, X_7, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[1] */
        ldr curB, [inB, #1*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_1, X_2, X_3, X_4, X_5, X_6, X_7,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_2, X_3, X_4, X_5, X_6, X_7, X_0,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_1, twist
        montgomery_fixup X_1, X_2, X_3, X_4, X_5, X_6, X_7, X_0, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[2] */
        ldr curB, [inB, #2*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_2, X_3, X_4, X_5, X_6, X_7, X_0,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_3, X_4, X_5, X_6, X_7, X_0, X_1,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_2, twist
        montgomery_fixup X_2, X_3, X_4, X_5, X_6, X_7, X_0, X_1, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[3] */
        ldr curB, [inB, #3*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_3, X_4, X_5, X_6, X_7, X_0, X_1,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_4, X_5, X_6, X_7, X_0, X_1, X_2,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_3, twist
        montgomery_fixup X_3, X_4, X_5, X_6, X_7, X_0, X_1, X_2, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[4] */
        ldr curB, [inB, #4*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_4, X_5, X_6, X_7, X_0, X_1, X_2,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_5, X_6, X_7, X_0, X_1, X_2, X_3,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_4, twist
        montgomery_fixup X_4, X_5, X_6, X_7, X_0, X_1, X_2, X_3, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[5] */
        ldr curB, [inB, #5*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_5, X_6, X_7, X_0, X_1, X_2, X_3,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_6, X_7, X_0, X_1, X_2, X_3, X_4,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_5, twist
        montgomery_fixup X_5, X_6, X_7, X_0, X_1, X_2, X_3, X_4, X_t, T_0, T_1, T_2, T_3, T_4, T_5

        ldp M_0, M_1, [mod, #0*8]
        ldp M_2, M_3, [mod, #2*8]
        ldp M_4, M_5, [mod, #4*8]

        borrow .req A_0
        fixup  .req A_1
        carry  .req X_4

        ldp T_0, T_1, [sp, #(16*2)]
        ldp T_2, T_3, [sp, #(16*3)]
        ldp T_4, T_5, [sp, #(16*4)]

        .unreq T_0
        .unreq T_1
        .unreq T_2
        .unreq T_3
        .unreq T_4
        .unreq T_5

        .unreq A_0
        .unreq A_1
        .unreq A_2
        .unreq A_3
        .unreq A_4
        .unreq A_5

        cond_sub X_6, X_7, X_0, X_1, X_2, X_3, \
                 M_0, M_1, M_2, M_3, M_4, M_5, \
                 carry, borrow,                \
                 M_0, M_1, M_2, M_3, M_4, M_5

        stp X_6, X_7,   [dst, #0*8]
        stp X_0, X_1,   [dst, #2*8]
        stp X_2, X_3,   [dst, #4*8]

        ldp x19, x20, [sp, #(16*0)]
        ldp x21, x22, [sp, #(16*1)]
        ldp x29, x30, [sp, #(16*5)]
        add sp, sp, #12*8

        ret

        .unreq inB
        .unreq dst

        .unreq X_0
        .unreq X_1
        .unreq X_2
        .unreq X_3
        .unreq X_4
        .unreq X_5
        .unreq X_6
        .unreq X_7


        .unreq M_0
        .unreq M_1
        .unreq M_2
        .unreq M_3
        .unreq M_4
        .unreq M_5

        .unreq curB
        .unreq mod


.type montmul_384_384, %function
.global montmul_384_384
montmul_384_384:
        inA   .req x1
        inB   .req x2
        mod   .req x3
        twist .req x4
        dst   .req x0

        X_0  .req x1
        X_1  .req x30
        X_2  .req x5
        X_3  .req x6
        X_4  .req x7
        X_5  .req x8
        X_6  .req x9
        X_7  .req x10

        A_0  .req x11
        A_1  .req x12
        A_2  .req x13
        A_3  .req x14
        A_4  .req x15
        A_5  .req x16

        M_0  .req x17
        M_1  .req x18
        M_2  .req x19
        M_3  .req x20
        M_4  .req x21
        M_5  .req x22

        T_0  .req x23
        T_1  .req x24
        T_2  .req x25
        T_3  .req x26
        T_4  .req x27
        T_5  .req x28

        curB .req x29
        X_t  .req curB

        save_gprs

        ldp A_0, A_1, [inA, #0*8]
        ldp A_2, A_3, [inA, #2*8]
        ldp A_4, A_5, [inA, #4*8]

        ldp M_0, M_1, [mod, #0*8]
        ldp M_2, M_3, [mod, #2*8]
        ldp M_4, M_5, [mod, #4*8]

        .unreq inA

        mov X_6, xzr

        /* X = A * B[0] */
        ldr curB, [inB, #0*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  X_0, X_1, X_2, X_3, X_4, X_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6      X_1, X_2, X_3, X_4, X_5, X_6,             T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_0, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,      X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_0, X_1, X_2, X_3, X_4, X_5, X_6,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,      X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_1, X_2, X_3, X_4, X_5, X_6, X_7,        T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[1] */
        ldr curB, [inB, #1*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_1, X_2, X_3, X_4, X_5, X_6, X_7,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_2, X_3, X_4, X_5, X_6, X_7, X_0,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_1, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext3 X_1, X_2, X_3, X_4, X_5, X_6, X_7, X_0,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_2, X_3, X_4, X_5, X_6, X_7, X_0,              T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[2] */
        ldr curB, [inB, #2*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_2, X_3, X_4, X_5, X_6, X_7, X_0,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_3, X_4, X_5, X_6, X_7, X_0, X_1,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_2, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext3 X_2, X_3, X_4, X_5, X_6, X_7, X_0, X_1,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_3, X_4, X_5, X_6, X_7, X_0, X_1,              T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[3] */
        ldr curB, [inB, #3*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_3, X_4, X_5, X_6, X_7, X_0, X_1,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_4, X_5, X_6, X_7, X_0, X_1, X_2,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_3, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext3 X_3, X_4, X_5, X_6, X_7, X_0, X_1, X_2,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_4, X_5, X_6, X_7, X_0, X_1, X_2,              T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[4] */
        ldr curB, [inB, #4*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_4, X_5, X_6, X_7, X_0, X_1, X_2,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_5, X_6, X_7, X_0, X_1, X_2, X_3,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_4, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext3 X_4, X_5, X_6, X_7, X_0, X_1, X_2, X_3,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_5, X_6, X_7, X_0, X_1, X_2, X_3,              T_0, T_1, T_2, T_3, T_4, T_5

        /* X += A * B[5] */
        ldr curB, [inB, #5*8]
        mul_low_x6  A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_5, X_6, X_7, X_0, X_1, X_2, X_3,        T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 A_0, A_1, A_2, A_3, A_4, A_5,      curB,  T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext  X_6, X_7, X_0, X_1, X_2, X_3, X_4,        T_0, T_1, T_2, T_3, T_4, T_5
        /* X += M * X[0]_twisted */
        mul         X_t, X_5, twist
        mul_low_x6  M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext3 X_5, X_6, X_7, X_0, X_1, X_2, X_3, X_4,         T_0, T_1, T_2, T_3, T_4, T_5
        mul_high_x6 M_0, M_1, M_2, M_3, M_4, M_5,            X_t,   T_0, T_1, T_2, T_3, T_4, T_5
        add_x6_ext2 X_6, X_7, X_0, X_1, X_2, X_3, X_4,              T_0, T_1, T_2, T_3, T_4, T_5

        borrow .req A_0
        fixup  .req A_1
        carry  .req X_4

        .unreq T_0
        .unreq T_1
        .unreq T_2
        .unreq T_3
        .unreq T_4
        .unreq T_5

        .unreq A_0
        .unreq A_1
        .unreq A_2
        .unreq A_3
        .unreq A_4
        .unreq A_5

        cond_sub X_6, X_7, X_0, X_1, X_2, X_3, \
                 M_0, M_1, M_2, M_3, M_4, M_5, \
                 carry, borrow,                \
                 M_0, M_1, M_2, M_3, M_4, M_5

        stp X_6, X_7,   [dst, #0*8]
        stp X_0, X_1,   [dst, #2*8]
        stp X_2, X_3,   [dst, #4*8]

        restore_gprs
        ret

        .unreq inB
        .unreq dst

        .unreq X_0
        .unreq X_1
        .unreq X_2
        .unreq X_3
        .unreq X_4
        .unreq X_5
        .unreq X_6
        .unreq X_7


        .unreq M_0
        .unreq M_1
        .unreq M_2
        .unreq M_3
        .unreq M_4
        .unreq M_5

        .unreq curB
        .unreq mod
