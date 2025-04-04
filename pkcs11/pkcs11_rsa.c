/* pkcs11_rsa.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifndef NO_RSA
static const unsigned char client_key_der_2048[] =
{
        0x30, 0x82, 0x04, 0xA4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
        0x01, 0x00, 0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4, 0x32,
        0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C, 0x74, 0x9A,
        0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47, 0xD6, 0xA6, 0x36, 0xB2,
        0x07, 0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44,
        0x9E, 0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67,
        0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2, 0x1B, 0xF7,
        0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF, 0xEC, 0xF1, 0x81, 0x1E,
        0x7B, 0x9B, 0x03, 0x47, 0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65,
        0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34, 0xF7,
        0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A, 0x7A, 0x78,
        0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D, 0xD2,
        0x3C, 0x40, 0x9C, 0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37, 0x51,
        0x1B, 0x0C, 0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35, 0xE4,
        0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF, 0x4E, 0x97, 0xD0,
        0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81, 0xAF, 0x20, 0x0B, 0x43,
        0x14, 0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F, 0x8D, 0x86,
        0xC2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40, 0x72,
        0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0, 0xCE, 0xEF,
        0x19, 0xCD, 0xAE, 0xFF, 0x78, 0x6C, 0x7B, 0xC0, 0x12, 0x03,
        0xD4, 0x4E, 0x72, 0x0D, 0x50, 0x6D, 0x3B, 0xA3, 0x3B, 0xA3,
        0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9, 0x8A,
        0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB, 0xFF, 0x25,
        0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40, 0x18,
        0x13, 0xB0, 0x63, 0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97, 0x84,
        0x86, 0x2D, 0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0, 0xAE,
        0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA, 0xD3, 0x02, 0x03,
        0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0xA2, 0xE6,
        0xD8, 0x5F, 0x10, 0x71, 0x64, 0x08, 0x9E, 0x2E, 0x6D, 0xD1,
        0x6D, 0x1E, 0x85, 0xD2, 0x0A, 0xB1, 0x8C, 0x47, 0xCE, 0x2C,
        0x51, 0x6A, 0xA0, 0x12, 0x9E, 0x53, 0xDE, 0x91, 0x4C, 0x1D,
        0x6D, 0xEA, 0x59, 0x7B, 0xF2, 0x77, 0xAA, 0xD9, 0xC6, 0xD9,
        0x8A, 0xAB, 0xD8, 0xE1, 0x16, 0xE4, 0x63, 0x26, 0xFF, 0xB5,
        0x6C, 0x13, 0x59, 0xB8, 0xE3, 0xA5, 0xC8, 0x72, 0x17, 0x2E,
        0x0C, 0x9F, 0x6F, 0xE5, 0x59, 0x3F, 0x76, 0x6F, 0x49, 0xB1,
        0x11, 0xC2, 0x5A, 0x2E, 0x16, 0x29, 0x0D, 0xDE, 0xB7, 0x8E,
        0xDC, 0x40, 0xD5, 0xA2, 0xEE, 0xE0, 0x1E, 0xA1, 0xF4, 0xBE,
        0x97, 0xDB, 0x86, 0x63, 0x96, 0x14, 0xCD, 0x98, 0x09, 0x60,
        0x2D, 0x30, 0x76, 0x9C, 0x3C, 0xCD, 0xE6, 0x88, 0xEE, 0x47,
        0x92, 0x79, 0x0B, 0x5A, 0x00, 0xE2, 0x5E, 0x5F, 0x11, 0x7C,
        0x7D, 0xF9, 0x08, 0xB7, 0x20, 0x06, 0x89, 0x2A, 0x5D, 0xFD,
        0x00, 0xAB, 0x22, 0xE1, 0xF0, 0xB3, 0xBC, 0x24, 0xA9, 0x5E,
        0x26, 0x0E, 0x1F, 0x00, 0x2D, 0xFE, 0x21, 0x9A, 0x53, 0x5B,
        0x6D, 0xD3, 0x2B, 0xAB, 0x94, 0x82, 0x68, 0x43, 0x36, 0xD8,
        0xF6, 0x2F, 0xC6, 0x22, 0xFC, 0xB5, 0x41, 0x5D, 0x0D, 0x33,
        0x60, 0xEA, 0xA4, 0x7D, 0x7E, 0xE8, 0x4B, 0x55, 0x91, 0x56,
        0xD3, 0x5C, 0x57, 0x8F, 0x1F, 0x94, 0x17, 0x2F, 0xAA, 0xDE,
        0xE9, 0x9E, 0xA8, 0xF4, 0xCF, 0x8A, 0x4C, 0x8E, 0xA0, 0xE4,
        0x56, 0x73, 0xB2, 0xCF, 0x4F, 0x86, 0xC5, 0x69, 0x3C, 0xF3,
        0x24, 0x20, 0x8B, 0x5C, 0x96, 0x0C, 0xFA, 0x6B, 0x12, 0x3B,
        0x9A, 0x67, 0xC1, 0xDF, 0xC6, 0x96, 0xB2, 0xA5, 0xD5, 0x92,
        0x0D, 0x9B, 0x09, 0x42, 0x68, 0x24, 0x10, 0x45, 0xD4, 0x50,
        0xE4, 0x17, 0x39, 0x48, 0xD0, 0x35, 0x8B, 0x94, 0x6D, 0x11,
        0xDE, 0x8F, 0xCA, 0x59, 0x02, 0x81, 0x81, 0x00, 0xEA, 0x24,
        0xA7, 0xF9, 0x69, 0x33, 0xE9, 0x71, 0xDC, 0x52, 0x7D, 0x88,
        0x21, 0x28, 0x2F, 0x49, 0xDE, 0xBA, 0x72, 0x16, 0xE9, 0xCC,
        0x47, 0x7A, 0x88, 0x0D, 0x94, 0x57, 0x84, 0x58, 0x16, 0x3A,
        0x81, 0xB0, 0x3F, 0xA2, 0xCF, 0xA6, 0x6C, 0x1E, 0xB0, 0x06,
        0x29, 0x00, 0x8F, 0xE7, 0x77, 0x76, 0xAC, 0xDB, 0xCA, 0xC7,
        0xD9, 0x5E, 0x9B, 0x3F, 0x26, 0x90, 0x52, 0xAE, 0xFC, 0x38,
        0x90, 0x00, 0x14, 0xBB, 0xB4, 0x0F, 0x58, 0x94, 0xE7, 0x2F,
        0x6A, 0x7E, 0x1C, 0x4F, 0x41, 0x21, 0xD4, 0x31, 0x59, 0x1F,
        0x4E, 0x8A, 0x1A, 0x8D, 0xA7, 0x57, 0x6C, 0x22, 0xD8, 0xE5,
        0xF4, 0x7E, 0x32, 0xA6, 0x10, 0xCB, 0x64, 0xA5, 0x55, 0x03,
        0x87, 0xA6, 0x27, 0x05, 0x8C, 0xC3, 0xD7, 0xB6, 0x27, 0xB2,
        0x4D, 0xBA, 0x30, 0xDA, 0x47, 0x8F, 0x54, 0xD3, 0x3D, 0x8B,
        0x84, 0x8D, 0x94, 0x98, 0x58, 0xA5, 0x02, 0x81, 0x81, 0x00,
        0xD5, 0x38, 0x1B, 0xC3, 0x8F, 0xC5, 0x93, 0x0C, 0x47, 0x0B,
        0x6F, 0x35, 0x92, 0xC5, 0xB0, 0x8D, 0x46, 0xC8, 0x92, 0x18,
        0x8F, 0xF5, 0x80, 0x0A, 0xF7, 0xEF, 0xA1, 0xFE, 0x80, 0xB9,
        0xB5, 0x2A, 0xBA, 0xCA, 0x18, 0xB0, 0x5D, 0xA5, 0x07, 0xD0,
        0x93, 0x8D, 0xD8, 0x9C, 0x04, 0x1C, 0xD4, 0x62, 0x8E, 0xA6,
        0x26, 0x81, 0x01, 0xFF, 0xCE, 0x8A, 0x2A, 0x63, 0x34, 0x35,
        0x40, 0xAA, 0x6D, 0x80, 0xDE, 0x89, 0x23, 0x6A, 0x57, 0x4D,
        0x9E, 0x6E, 0xAD, 0x93, 0x4E, 0x56, 0x90, 0x0B, 0x6D, 0x9D,
        0x73, 0x8B, 0x0C, 0xAE, 0x27, 0x3D, 0xDE, 0x4E, 0xF0, 0xAA,
        0xC5, 0x6C, 0x78, 0x67, 0x6C, 0x94, 0x52, 0x9C, 0x37, 0x67,
        0x6C, 0x2D, 0xEF, 0xBB, 0xAF, 0xDF, 0xA6, 0x90, 0x3C, 0xC4,
        0x47, 0xCF, 0x8D, 0x96, 0x9E, 0x98, 0xA9, 0xB4, 0x9F, 0xC5,
        0xA6, 0x50, 0xDC, 0xB3, 0xF0, 0xFB, 0x74, 0x17, 0x02, 0x81,
        0x80, 0x5E, 0x83, 0x09, 0x62, 0xBD, 0xBA, 0x7C, 0xA2, 0xBF,
        0x42, 0x74, 0xF5, 0x7C, 0x1C, 0xD2, 0x69, 0xC9, 0x04, 0x0D,
        0x85, 0x7E, 0x3E, 0x3D, 0x24, 0x12, 0xC3, 0x18, 0x7B, 0xF3,
        0x29, 0xF3, 0x5F, 0x0E, 0x76, 0x6C, 0x59, 0x75, 0xE4, 0x41,
        0x84, 0x69, 0x9D, 0x32, 0xF3, 0xCD, 0x22, 0xAB, 0xB0, 0x35,
        0xBA, 0x4A, 0xB2, 0x3C, 0xE5, 0xD9, 0x58, 0xB6, 0x62, 0x4F,
        0x5D, 0xDE, 0xE5, 0x9E, 0x0A, 0xCA, 0x53, 0xB2, 0x2C, 0xF7,
        0x9E, 0xB3, 0x6B, 0x0A, 0x5B, 0x79, 0x65, 0xEC, 0x6E, 0x91,
        0x4E, 0x92, 0x20, 0xF6, 0xFC, 0xFC, 0x16, 0xED, 0xD3, 0x76,
        0x0C, 0xE2, 0xEC, 0x7F, 0xB2, 0x69, 0x13, 0x6B, 0x78, 0x0E,
        0x5A, 0x46, 0x64, 0xB4, 0x5E, 0xB7, 0x25, 0xA0, 0x5A, 0x75,
        0x3A, 0x4B, 0xEF, 0xC7, 0x3C, 0x3E, 0xF7, 0xFD, 0x26, 0xB8,
        0x20, 0xC4, 0x99, 0x0A, 0x9A, 0x73, 0xBE, 0xC3, 0x19, 0x02,
        0x81, 0x81, 0x00, 0xBA, 0x44, 0x93, 0x14, 0xAC, 0x34, 0x19,
        0x3B, 0x5F, 0x91, 0x60, 0xAC, 0xF7, 0xB4, 0xD6, 0x81, 0x05,
        0x36, 0x51, 0x53, 0x3D, 0xE8, 0x65, 0xDC, 0xAF, 0x2E, 0xDC,
        0x61, 0x3E, 0xC9, 0x7D, 0xB8, 0x7F, 0x87, 0xF0, 0x3B, 0x9B,
        0x03, 0x82, 0x29, 0x37, 0xCE, 0x72, 0x4E, 0x11, 0xD5, 0xB1,
        0xC1, 0x0C, 0x07, 0xA0, 0x99, 0x91, 0x4A, 0x8D, 0x7F, 0xEC,
        0x79, 0xCF, 0xF1, 0x39, 0xB5, 0xE9, 0x85, 0xEC, 0x62, 0xF7,
        0xDA, 0x7D, 0xBC, 0x64, 0x4D, 0x22, 0x3C, 0x0E, 0xF2, 0xD6,
        0x51, 0xF5, 0x87, 0xD8, 0x99, 0xC0, 0x11, 0x20, 0x5D, 0x0F,
        0x29, 0xFD, 0x5B, 0xE2, 0xAE, 0xD9, 0x1C, 0xD9, 0x21, 0x56,
        0x6D, 0xFC, 0x84, 0xD0, 0x5F, 0xED, 0x10, 0x15, 0x1C, 0x18,
        0x21, 0xE7, 0xC4, 0x3D, 0x4B, 0xD7, 0xD0, 0x9E, 0x6A, 0x95,
        0xCF, 0x22, 0xC9, 0x03, 0x7B, 0x9E, 0xE3, 0x60, 0x01, 0xFC,
        0x2F, 0x02, 0x81, 0x80, 0x11, 0xD0, 0x4B, 0xCF, 0x1B, 0x67,
        0xB9, 0x9F, 0x10, 0x75, 0x47, 0x86, 0x65, 0xAE, 0x31, 0xC2,
        0xC6, 0x30, 0xAC, 0x59, 0x06, 0x50, 0xD9, 0x0F, 0xB5, 0x70,
        0x06, 0xF7, 0xF0, 0xD3, 0xC8, 0x62, 0x7C, 0xA8, 0xDA, 0x6E,
        0xF6, 0x21, 0x3F, 0xD3, 0x7F, 0x5F, 0xEA, 0x8A, 0xAB, 0x3F,
        0xD9, 0x2A, 0x5E, 0xF3, 0x51, 0xD2, 0xC2, 0x30, 0x37, 0xE3,
        0x2D, 0xA3, 0x75, 0x0D, 0x1E, 0x4D, 0x21, 0x34, 0xD5, 0x57,
        0x70, 0x5C, 0x89, 0xBF, 0x72, 0xEC, 0x4A, 0x6E, 0x68, 0xD5,
        0xCD, 0x18, 0x74, 0x33, 0x4E, 0x8C, 0x3A, 0x45, 0x8F, 0xE6,
        0x96, 0x40, 0xEB, 0x63, 0xF9, 0x19, 0x86, 0x3A, 0x51, 0xDD,
        0x89, 0x4B, 0xB0, 0xF3, 0xF9, 0x9F, 0x5D, 0x28, 0x95, 0x38,
        0xBE, 0x35, 0xAB, 0xCA, 0x5C, 0xE7, 0x93, 0x53, 0x34, 0xA1,
        0x45, 0x5D, 0x13, 0x39, 0x65, 0x42, 0x46, 0xA1, 0x9F, 0xCD,
        0xF5, 0xBF
};
static const int sizeof_client_key_der_2048 = sizeof(client_key_der_2048);

static const unsigned char client_keypub_der_2048[] =
{
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
        0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
        0x01, 0x01, 0x00, 0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4,
        0x32, 0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C, 0x74,
        0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47, 0xD6, 0xA6, 0x36,
        0xB2, 0x07, 0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6, 0xC3,
        0x44, 0x9E, 0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B,
        0x67, 0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A, 0xD2, 0x1B,
        0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF, 0xEC, 0xF1, 0x81,
        0x1E, 0x7B, 0x9B, 0x03, 0x47, 0x9A, 0xBF, 0x65, 0xCC, 0x7F,
        0x65, 0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34,
        0xF7, 0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A, 0x7A,
        0x78, 0xE1, 0x01, 0x56, 0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D,
        0xD2, 0x3C, 0x40, 0x9C, 0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37,
        0x51, 0x1B, 0x0C, 0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35,
        0xE4, 0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF, 0x4E, 0x97,
        0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81, 0xAF, 0x20, 0x0B,
        0x43, 0x14, 0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F, 0x8D,
        0x86, 0xC2, 0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40,
        0x72, 0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73, 0xB0, 0xCE,
        0xEF, 0x19, 0xCD, 0xAE, 0xFF, 0x78, 0x6C, 0x7B, 0xC0, 0x12,
        0x03, 0xD4, 0x4E, 0x72, 0x0D, 0x50, 0x6D, 0x3B, 0xA3, 0x3B,
        0xA3, 0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9,
        0x8A, 0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB, 0xFF,
        0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40,
        0x18, 0x13, 0xB0, 0x63, 0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97,
        0x84, 0x86, 0x2D, 0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0,
        0xAE, 0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA, 0xD3, 0x02,
        0x03, 0x01, 0x00, 0x01
};
static const int sizeof_client_keypub_der_2048 = sizeof(client_keypub_der_2048);
WC_RNG rng;

static int decode_private_key(RsaKey* key, int devId)
{
    int    ret;
    word32 idx = 0;

    fprintf(stderr, "Decode Private RSA Key\n");
    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize RSA key: %d\n", ret);
    }
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, key,
                (word32)sizeof_client_key_der_2048);
        if (ret != 0)
            fprintf(stderr, "Failed to decode private key: %d\n", ret);
    }

    return ret;
}

static int decode_public_key(RsaKey* key, int devId)
{
    int    ret;
    word32 idx = 0;

    fprintf(stderr, "Decode Public RSA Key\n");
    ret = wc_InitRsaKey_ex(key, NULL, devId);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize RSA key: %d\n", ret);
    }
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecode(client_keypub_der_2048, &idx, key,
                (word32)sizeof_client_keypub_der_2048);
        if (ret != 0)
            fprintf(stderr, "Failed to decode public key: %d\n", ret);
    }

    return ret;
}

static int rsa_sign_verify(int devId)
{
    int    ret = 0;
    byte   hash[32], pt[32], sig[2048/8];
    word32 hashSz, ptSz, sigSz;
    RsaKey priv;
    RsaKey pub;

    memset(hash, 9, sizeof(hash));
    hashSz = sizeof(hash);
    sigSz = sizeof(sig);
    ptSz = sizeof(pt);

    ret = decode_private_key(&priv, devId);
    if (ret == 0) {
        fprintf(stderr, "Signing\n");
        sigSz = ret = wc_RsaSSL_Sign(hash, hashSz, sig, (int)sigSz, &priv,
                                     &rng);
        if (ret < 0)
            fprintf(stderr, "Failed to sign: %d\n", ret);
        else
            ret = 0;

        wc_FreeRsaKey(&priv);
    }

    if (ret == 0) {
        ret = decode_public_key(&pub, devId);
        if (ret == 0) {
            fprintf(stderr, "Verifying\n");
            ret = wc_RsaSSL_Verify(sig, sigSz, pt, (int)ptSz, &pub);
            if (ret < 0)
                fprintf(stderr, "Failed to verify: %d\n", ret);

            if (XMEMCMP(hash, pt, ret) != 0) {
                fprintf(stderr, "Failed to verify\n");
            }

            wc_FreeRsaKey(&pub);
            ret = 0;
        }
    }

    return ret;
}

#ifdef WC_RSA_PSS
static int rsa_sign_verify_pss(int devId)
{
    int    ret = 0;
    byte   hash[32], pt[2048/8], sig[2048/8];
    word32 hashSz, ptSz, sigSz;
    RsaKey priv;
    RsaKey pub;

    memset(hash, 9, sizeof(hash));
    hashSz = sizeof(hash);
    sigSz = sizeof(sig);
    ptSz = sizeof(pt);

    ret = decode_private_key(&priv, devId);
    if (ret == 0) {
        fprintf(stderr, "PSS Signing\n");
        sigSz = ret = wc_RsaPSS_Sign(hash, hashSz, sig, (int)sigSz,
                    WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &priv, &rng);
        if (ret < 0)
            fprintf(stderr, "Failed to sign: %d\n", ret);
        else
            ret = 0;

        wc_FreeRsaKey(&priv);
    }

    if (ret == 0) {
        ret = decode_public_key(&pub, devId);
        if (ret == 0) {
            fprintf(stderr, "PSS Verifying\n");
            ret = wc_RsaPSS_VerifyCheck(sig, sigSz, pt, ptSz, hash, hashSz,
                                    WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &pub);
            if (ret < 0)
                fprintf(stderr, "Failed to verify: %d\n", ret);
            else
                ret = 0;

            wc_FreeRsaKey(&pub);
        }
    }

    return ret;
}
#endif /* ifdef WC_RSA_PSS */

/* Define maximum RSA key size in bits */
#define MAX_RSA_KEY_BITS 2048

static int rsa_encrypt_decrypt(int devId)
{
    int    ret = 0;
    byte   plain[128], out[MAX_RSA_KEY_BITS/8], dec[MAX_RSA_KEY_BITS/8];
    word32 plainSz, outSz, decSz;
    RsaKey pub;
    RsaKey priv;

    /* Initialize plain text buffer with 9's as sample data */
    memset(plain, 9, sizeof(plain));
    plainSz = (word32)sizeof(plain);
    outSz = (word32)sizeof(out);
    decSz = (word32)sizeof(dec);

    /* Encrypt with public key */
    ret = decode_public_key(&pub, devId);
    if (ret == 0) {
        fprintf(stderr, "RSA Public Encrypt\n");
        
#ifdef WC_RSA_BLINDING
        ret = wc_RsaSetRNG(&pub, &rng);
        if (ret != 0)
            fprintf(stderr, "Failed to set RNG: %d\n", ret);
#endif

        if (ret == 0) {
            outSz = ret = wc_RsaPublicEncrypt_ex(plain, plainSz, out, (int)outSz,
                &pub, &rng, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, 
                NULL, 0);
            if (ret < 0)
                fprintf(stderr, "Failed to perform public encrypt: %d\n", ret);
            else
                ret = 0;
        }
        
        wc_FreeRsaKey(&pub);
    }

    /* Decrypt with private key */
    if (ret == 0) {
        ret = decode_private_key(&priv, devId);
        if (ret == 0) {
            fprintf(stderr, "RSA Private Decrypt\n");
            
#ifdef WC_RSA_BLINDING
            ret = wc_RsaSetRNG(&priv, &rng);
            if (ret != 0)
                fprintf(stderr, "Failed to set RNG: %d\n", ret);
#endif

            if (ret == 0) {
                decSz = ret = wc_RsaPrivateDecrypt_ex(out, outSz, dec, (int)decSz, 
                    &priv, WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, WC_MGF1NONE, 
                    NULL, 0);
                if (ret < 0)
                    fprintf(stderr, "Failed to perform private decrypt: %d\n", ret);
                else
                    ret = 0;
            }

            /* Verify the decrypted data matches the original */
            if (ret == 0) {
                if (decSz != plainSz || memcmp(plain, dec, decSz) != 0) {
                    fprintf(stderr, "Decrypted data does not match plain text\n");
                    ret = -1;
                }
                else {
                    fprintf(stderr, "Decryption successful\n");
                }
            }
            
            wc_FreeRsaKey(&priv);
        }
    }

    return ret;
}
#endif /* ifndef NO_RSA */

int main(int argc, char* argv[])
{
    int ret;
    const char* library;
    const char* slot;
    const char* tokenName;
    const char* userPin;
    Pkcs11Dev dev;
    Pkcs11Token token;
    int slotId;
    int devId = 1;

    if (argc != 4 && argc != 5) {
        fprintf(stderr,
                "Usage: pkcs11_rsa <libname> <slot> <tokenname> [userpin]\n");
        return 1;
    }

    library = argv[1];
    slot = argv[2];
    tokenName = argv[3];
    userPin = (argc == 4) ? NULL : argv[4];
    slotId = atoi(slot);

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif
    wolfCrypt_Init();

    ret = wc_Pkcs11_Initialize(&dev, library, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize PKCS#11 library\n");
        ret = 2;
    }
    else {
        ret = wc_Pkcs11Token_Init(&token, &dev, slotId, tokenName,
            (byte*)userPin, userPin == NULL ? 0 : strlen(userPin));
        if (ret != 0) {
            fprintf(stderr, "Failed to initialize PKCS#11 token\n");
            ret = 2;
        }
        else {
            ret = wc_CryptoDev_RegisterDevice(devId, wc_Pkcs11_CryptoDevCb,
                                              &token);
            if (ret != 0) {
                fprintf(stderr, "Failed to register PKCS#11 token\n");
                ret = 2;
            }
            if (ret == 0) {
                ret = wc_InitRng(&rng);
                if (ret != 0) {
                    fprintf(stderr, "Failed to initialize RNG: %d\n", ret);
                }
            }
            if (ret == 0) {
            #ifndef NO_RSA
                ret = rsa_sign_verify(devId);
                if (ret != 0)
                    ret = 1;
            #ifdef WC_RSA_PSS
                if (ret == 0) {
                    ret = rsa_sign_verify_pss(devId);
                    if (ret != 0)
                        ret = 1;
                }
            #endif
                if (ret == 0) {
                    ret = rsa_encrypt_decrypt(devId);
                    if (ret != 0)
                        ret = 1;
                }
            #endif
            }
            wc_Pkcs11Token_Final(&token);
        }
        wc_Pkcs11_Finalize(&dev);
    }

    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    if (ret == 0)
        fprintf(stderr, "Success\n");

    return ret;
}

