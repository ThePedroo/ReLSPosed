#pragma once

/*
 * This decoder is made by frknkrc44.
 *
 * Thanks DanGLES3 and fatalcoder524 to find memory leaks.
 */

const char startMagic[4] = { 'A', 'B', 'X', '\0' };

static const short TOKEN_START_DOCUMENT = 0;
static const short TOKEN_END_DOCUMENT = 1;
static const short TOKEN_START_TAG = 2;
static const short TOKEN_END_TAG = 3;
static const short TOKEN_TEXT = 4;
static const short TOKEN_CDSECT = 5;
// static const short TOKEN_ENTITY_REF = 6;
static const short TOKEN_IGNORABLE_WHITESPACE = 7;
static const short TOKEN_PROCESSING_INSTRUCTION = 8;
static const short TOKEN_COMMENT = 9;
static const short TOKEN_DOCDECL = 10;
static const short TOKEN_ATTRIBUTE = 15;

static const short DATA_NULL = 1 << 4;
static const short DATA_STRING = 2 << 4;
static const short DATA_STRING_INTERNED = 3 << 4;
static const short DATA_BYTES_HEX = 4 << 4;
static const short DATA_BYTES_BASE64 = 5 << 4;
static const short DATA_INT = 6 << 4;
static const short DATA_INT_HEX = 7 << 4;
static const short DATA_LONG = 8 << 4;
static const short DATA_LONG_HEX = 9 << 4;
static const short DATA_FLOAT = 10 << 4;
static const short DATA_DOUBLE = 11 << 4;
static const short DATA_BOOLEAN_TRUE = 12 << 4;
static const short DATA_BOOLEAN_FALSE = 13 << 4;
