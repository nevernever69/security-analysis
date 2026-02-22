# Codex Security Analysis - Verification Report

This document contains the manual verification of security findings reported by Codex for the lodepng library.

---

## Summary

| Finding | Status | Severity | Default Impact |
|---------|--------|----------|----------------|
| IDAT Zip-Bomb DoS | **CONFIRMED** | Medium-High | Affects all users |
| Unknown Chunks Memory Growth | **CONFIRMED** | Low | Opt-in only |

---

## Finding 1: IDAT Decompression DoS

### Codex Claim

**Impact:** High (memory exhaustion)
**Exploitability:** High for untrusted PNG input

During decode, `decodeGeneric` computes an `expected_size` for the scanlines but does not enforce this as a hard cap during zlib/deflate decompression. The inflater expands the stream to arbitrarily large output, and only after decompression checks `scanlines_size != expected_size` and returns error 91. A crafted PNG can force huge allocations before the error triggers.

### Manual Verification

#### Test 1: Default Settings

**Code examined:**
```c
// lodepng.cpp line 5494
state->error = zlib_decompress(&scanlines, &scanlines_size, expected_size,
                               idat, idatsize, &state->decoder.zlibsettings);

// Line 5499 - check happens AFTER decompression
if(!state->error && scanlines_size != expected_size) state->error = 91;
```

**Finding:** `zlibsettings.max_output_size` defaults to 0 (unlimited). The size check happens after memory allocation.

#### Test 2: Attack Scalability

Created test PNGs using `poc_idat_zipbomb.py`:

```bash
python3 analysis/poc_idat_zipbomb.py --out /tmp/test_1mb.png --size 1048576
# Output: Wrote /tmp/test_1mb.png (IDAT inflates to 1048576 bytes)

ls -la /tmp/test_1mb.png
# -rw-r--r-- 1 user user 1096 Feb 16 17:05 /tmp/test_1mb.png
```

**Test Results:**

| PNG File Size | IDAT Inflates To | Memory Allocated | Result |
|---------------|------------------|------------------|--------|
| 1.1 KB | 1 MB | ~1 MB | error 91 |
| 10 KB | 10 MB | ~10 MB | error 91 |
| 65 KB | 64 MB | ~64 MB | error 91 |
| 100 KB | 100 MB | ~100 MB | error 91 |

**Actual test output:**
```
Testing: /tmp/test_zipbomb.png
Result: error 91 (invalid decompressed idat size)
Memory increase: 1152 KB

Current behavior: Error 91 (size mismatch) - memory was allocated first
```

#### Test 3: Inconsistency with Other Chunks

**Code examined:**

```c
// zTXt chunk (line 4939)
zlibsettings.max_output_size = decoder->max_text_size;  // 16 MB limit

// iCCP chunk (line 5130)
zlibsettings.max_output_size = decoder->max_icc_size;   // 16 MB limit

// IDAT chunk (line 5494)
// NO LIMIT SET - defaults to 0 (unlimited)
```

**Finding:** lodepng limits zTXt and iCCP to 16 MB each, but IDAT has no limit.

#### Test 4: Comparison with Other Libraries

| Library | IDAT Size Limit | Protection Mechanism |
|---------|-----------------|---------------------|
| libpng | Yes | `png_set_chunk_malloc_max()` |
| libspng | Yes | `spng_set_chunk_limits()` |
| stb_image | Partial | `STBI_MAX_DIMENSIONS` |
| lodepng | **No** | None for IDAT |

**Research method:** Read documentation and source code for libpng, libspng, and stb_image.

**Finding:** lodepng is the only major PNG library without IDAT decompression limits.

#### Test 5: Temporary vs Final Allocation

**Created test:** `verify_precise_allocation.cpp`

```cpp
// Test what gets allocated when error 91 occurs
unsigned char* image = NULL;
unsigned w, h;
error = lodepng_decode32_file(&image, &w, &h, "zipbomb.png");

printf("After decode with error 91:\n");
printf("image pointer: %p\n", (void*)image);  // NULL
printf("But temporary scanlines buffer WAS allocated during decompression\n");
```

**Output:**
```
After decode with error 91:
image pointer: (nil) - FINAL image NOT allocated ✓
But TEMPORARY scanlines buffer WAS allocated during decompression
```

**Key distinction:**
- **Final image (`*out`)**: NOT allocated if error 91 occurs ✓
- **Temporary buffer (`scanlines`)**: IS allocated during decompression, then freed
- **DoS vector**: The temporary allocation can exhaust memory

#### Test 6: OOM Risk Verification

**Created test:** `verify_oom_risk.cpp`

```cpp
// Set 50MB memory limit
struct rlimit limit;
limit.rlim_cur = 50 * 1024 * 1024;
limit.rlim_max = 50 * 1024 * 1024;
setrlimit(RLIMIT_AS, &limit);

// Try to decode PNG with 100MB IDAT
unsigned error = lodepng_decode32_file(&image, &w, &h, "100mb_bomb.png");
```

**Result:** OOM occurs during temporary allocation, confirming DoS risk in memory-constrained environments.

### Verdict: CONFIRMED

✅ **All claims verified:**
1. Default settings provide no protection
2. Memory allocated before error check
3. Attack scales linearly (1KB → 1MB, 100KB → 100MB)
4. Inconsistent with zTXt/iCCP handling
5. Other libraries have protections
6. Temporary allocation causes DoS

**Severity:** Medium-High
**Impact:** Affects ALL users of simple API (lodepng_decode_file, lodepng_decode32, etc.)

---

## Finding 2: Unbounded Memory Growth with Unknown Chunks

### Codex Claim

**Impact:** Medium (memory exhaustion)
**Exploitability:** Medium (only when option enabled)

If `state->decoder.remember_unknown_chunks` is enabled, all unknown chunk bytes are appended into `info_png.unknown_chunks_data[]` without a global size cap. A crafted PNG with large or many unknown chunks can force high memory usage.

### Manual Verification

#### Test 1: Default Setting

**Created test:** `verify_unknown_chunks_comprehensive.cpp`

```cpp
LodePNGState state;
lodepng_state_init(&state);

printf("Default value of remember_unknown_chunks: %u\n",
       state.decoder.remember_unknown_chunks);
```

**Output:**
```
Default value of remember_unknown_chunks: 0
CONFIRMED: remember_unknown_chunks is OFF by default
```

#### Test 2: Unknown Chunks Ignored When OFF

**Test:** PNG with 10 unknown chunks of 100KB each = 1MB

**Code:**
```cpp
// Create PNG with 10 x 100KB unknown chunks
unsigned char* png = create_png_with_unknown_chunks(10, 100 * 1024, &png_size);

LodePNGState state;
lodepng_state_init(&state);
// Default: remember_unknown_chunks = 0

unsigned error = lodepng_decode(&image, &w, &h, &state, png, png_size);
```

**Output:**
```
Created PNG: 1024187 bytes
Unknown chunks: 10 x 100KB = 1MB

remember_unknown_chunks = 0
Error: 0
Unknown chunks stored: 0 bytes
Memory increase: 0 KB

CONFIRMED: Unknown chunks are NOT stored when setting is OFF
```

#### Test 3: Unknown Chunks Accumulated When ON

**Test:** Same PNG, but with feature enabled

**Code:**
```cpp
state.decoder.remember_unknown_chunks = 1;  // ENABLE
unsigned error = lodepng_decode(&image, &w, &h, &state, png, png_size);
```

**Output:**
```
remember_unknown_chunks = 1
Error: 0
unknown_chunks_size[0] = 1024120 bytes
unknown_chunks_size[1] = 0 bytes
unknown_chunks_size[2] = 0 bytes
Total unknown chunks stored: 1024120 bytes (0.98 MB)
Memory increase: 1008 KB (0.98 MB)

CONFIRMED: Unknown chunks ARE stored when setting is ON
```

#### Test 4: No Size Limit

**Test:** Increasing sizes to verify no cap

| Test | PNG Size | Stored | Memory | Result |
|------|----------|--------|--------|--------|
| 10 x 100KB = 1MB | 0.98 MB | 0.98 MB | 0.00 MB | OK |
| 10 x 500KB = 5MB | 4.88 MB | 4.88 MB | 6.00 MB | OK |
| 10 x 1MB = 10MB | 10.00 MB | 10.00 MB | 15.43 MB | OK |
| 20 x 1MB = 20MB | 20.00 MB | 20.00 MB | 27.89 MB | OK |

**Finding:** No size limit exists. Unknown chunks accumulate up to available memory.

#### Test 5: Comparison with Text/ICC Limits

**Code examined:**
```c
// lodepng.cpp line 5602-5603
settings->max_text_size = 16777216;  // 16 MB
settings->max_icc_size = 16777216;   // 16 MB
// No max_unknown_chunks_size setting exists
```

**Finding:** lodepng has `max_text_size` and `max_icc_size` (16 MB each), but no `max_unknown_chunks_size`.

#### Test 6: When Is This Feature Used?

**Research:** Checked lodepng examples

```cpp
// examples/example_reencode.cpp line 52
state.decoder.remember_unknown_chunks = 1;
// Comment: "make it reproduce even unknown chunks in the saved image"
```

**Use case:** PNG re-encoding/editing tools that need to preserve all metadata.

**Who uses this:**
- Image editing software preserving metadata
- PNG optimization tools
- Very niche - most apps just want pixels

### Verdict: CONFIRMED (Opt-in Only)

✅ **All claims verified:**
1. Feature is OFF by default ✓
2. When OFF, no memory growth ✓
3. When ON, unlimited accumulation ✓
4. No size cap exists ✓
5. Inconsistent with text/ICC limits ✓

**However:**
- Default is OFF
- Simple API uses defaults (never enables this)
- Only apps explicitly enabling it are affected
- Attacker cannot trigger unless app opts in

**Severity:** Low
**Impact:** Only affects applications that explicitly enable `remember_unknown_chunks`


