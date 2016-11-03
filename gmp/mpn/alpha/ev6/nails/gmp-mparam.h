/* gmp-mparam.h -- Compiler/machine parameter header file.

Copyright 1991, 1993, 1994, 1999-2004 Free Software Foundation, Inc.

This file is part of the GNU MP Library.

The GNU MP Library is free software; you can redistribute it and/or modify
it under the terms of either:

  * the GNU Lesser General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.

or

  * the GNU General Public License as published by the Free Software
    Foundation; either version 2 of the License, or (at your option) any
    later version.

or both in parallel, as here.

The GNU MP Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received copies of the GNU General Public License and the
GNU Lesser General Public License along with the GNU MP Library.  If not,
see https://www.gnu.org/licenses/.  */

#define GMP_LIMB_BITS 64
#define GMP_LIMB_BYTES 8

/* Generated by tuneup.c, 2004-02-07, gcc 3.3 */

#define MUL_TOOM22_THRESHOLD             40
#define MUL_TOOM33_THRESHOLD            236

#define SQR_BASECASE_THRESHOLD            7  /* karatsuba */
#define SQR_TOOM2_THRESHOLD               0  /* never sqr_basecase */
#define SQR_TOOM3_THRESHOLD             120

#define DIV_SB_PREINV_THRESHOLD       MP_SIZE_T_MAX  /* no preinv with nails */
#define DIV_DC_THRESHOLD                 48
#define POWM_THRESHOLD                  113

#define HGCD_THRESHOLD                   78
#define GCD_ACCEL_THRESHOLD               3
#define GCD_DC_THRESHOLD                392
#define JACOBI_BASE_METHOD                1

#define DIVREM_1_NORM_THRESHOLD       MP_SIZE_T_MAX  /* no preinv with nails */
#define DIVREM_1_UNNORM_THRESHOLD     MP_SIZE_T_MAX  /* no preinv with nails */
#define MOD_1_NORM_THRESHOLD          MP_SIZE_T_MAX  /* no preinv with nails */
#define MOD_1_UNNORM_THRESHOLD        MP_SIZE_T_MAX  /* no preinv with nails */
#define USE_PREINV_DIVREM_1               0  /* no preinv with nails */
#define USE_PREINV_MOD_1                  0  /* no preinv with nails */
#define DIVREM_2_THRESHOLD            MP_SIZE_T_MAX  /* no preinv with nails */
#define DIVEXACT_1_THRESHOLD              0  /* always */
#define MODEXACT_1_ODD_THRESHOLD          0  /* always */

#define GET_STR_DC_THRESHOLD             15
#define GET_STR_PRECOMPUTE_THRESHOLD     24
#define SET_STR_THRESHOLD              6336

#define MUL_FFT_TABLE  { 688, 1440, 3648, 6400, 25600, 0 }
#define MUL_FFT_MODF_THRESHOLD          488
#define MUL_FFT_THRESHOLD              3712

#define SQR_FFT_TABLE  { 432, 864, 3136, 6400, 25600, 0 }
#define SQR_FFT_MODF_THRESHOLD          480
#define SQR_FFT_THRESHOLD              2976
