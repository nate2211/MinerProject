// randomx_scan_extended_topk.cl
//
// VirtualASIC screening kernel with extended RandomX-state args and
// per-workgroup top-K candidate selection.
//
// This keeps only the strongest few candidates per workgroup instead of
// appending every screening hit, which reduces CPU verify waste.
//
// VirtualASIC metadata:
// @vasic_mode candidate_merge
// @vasic_count_arg 8
// @vasic_merge_buffer 9:36
// @vasic_partition global_offset
//
// ABI:
//   0:  __global const uchar* seed_hash
//   1:  __global const uchar* blob
//   2:  uint blob_len
//   3:  uint nonce_offset
//   4:  uint start_nonce
//   5:  uint target_lo
//   6:  uint target_hi
//   7:  uint max_results
//   8:  __global uint* out_count
//   9:  __global uchar* out_records
//   10: __global const uchar* randomx_cache
//   11: uint randomx_cache_bytes
//   12: __global const uchar* randomx_dataset
//   13: uint randomx_dataset_bytes
//   14: __global const uchar* randomx_vm_descriptor
//   15: uint randomx_vm_descriptor_bytes
//
// Output record format:
//   [0..3]   nonce_u32 little-endian
//   [4..35]  32-byte digest
//
// Honest limit:
// This is still a screening kernel, not a full RandomX implementation.
// It uses staged RandomX-related state to rank candidates more intelligently,
// but it does not execute the real RandomX VM.
//
// Recommended:
//   Keep local size <= RX_LOCAL_MAX (default 256)
//   Try RX_TOPK = 2..8
//   If candidate spam is still too high, increase strictness.
//
// Example stricter build:
//   -D RX_STRICT_SCREEN=1 -D RX_SECONDARY_MASK_BITS=4 -D RX_TOPK=4
//
// VirtualASIC CPU-lane note:
//   VirtualASIC may compile a CPU-lane variant with -DVASIC_CPU_LANE=1.
//   The section below reduces work for that path so CPU-side merged candidates
//   can contribute without exploding overhead.

#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_local_int32_base_atomics  : enable

#ifndef VASIC_CPU_LANE
#define VASIC_CPU_LANE 0
#endif

#ifndef RX_MAX_BLOB
#define RX_MAX_BLOB 256u
#endif

#ifndef RX_RATE_BYTES
#define RX_RATE_BYTES 136u
#endif

#ifndef RX_RATE_LANES
#define RX_RATE_LANES 17u
#endif

#ifndef RX_SAMPLE_BYTES
#define RX_SAMPLE_BYTES 64u
#endif

#ifndef RX_CACHE_SAMPLE_COUNT
#define RX_CACHE_SAMPLE_COUNT 4u
#endif

#ifndef RX_DATASET_SAMPLE_COUNT
#define RX_DATASET_SAMPLE_COUNT 6u
#endif

#ifndef RX_VM_SAMPLE_BYTES
#define RX_VM_SAMPLE_BYTES 64u
#endif

#ifndef RX_STRICT_SCREEN
#define RX_STRICT_SCREEN 0
#endif

#ifndef RX_SECONDARY_MASK_BITS
#define RX_SECONDARY_MASK_BITS 0u
#endif

#ifndef RX_FINAL_PASSES
#define RX_FINAL_PASSES 2u
#endif

#ifndef RX_TOPK
#define RX_TOPK 4u
#endif

#ifndef RX_LOCAL_MAX
#define RX_LOCAL_MAX 256u
#endif

#if VASIC_CPU_LANE
    #undef RX_TOPK
    #define RX_TOPK 2u

    #undef RX_CACHE_SAMPLE_COUNT
    #define RX_CACHE_SAMPLE_COUNT 2u

    #undef RX_DATASET_SAMPLE_COUNT
    #define RX_DATASET_SAMPLE_COUNT 2u

    #undef RX_FINAL_PASSES
    #define RX_FINAL_PASSES 1u

    #undef RX_VM_SAMPLE_BYTES
    #define RX_VM_SAMPLE_BYTES 32u
#endif

__constant ulong KECCAKF_RNDC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

__constant uint KECCAKF_ROTC[24] = {
    1u, 3u, 6u, 10u, 15u, 21u, 28u, 36u,
    45u, 55u, 2u, 14u, 27u, 41u, 56u, 8u,
    25u, 43u, 62u, 18u, 39u, 61u, 20u, 44u
};

__constant uint KECCAKF_PILN[24] = {
    10u, 7u, 11u, 17u, 18u, 3u, 5u, 16u,
    8u, 21u, 24u, 4u, 15u, 23u, 19u, 13u,
    12u, 2u, 20u, 14u, 22u, 9u, 6u, 1u
};

inline ulong rotl64(ulong x, uint y)
{
    y &= 63u;
    return (x << y) | (x >> ((64u - y) & 63u));
}

inline uint read_u32_le_private(const uchar* p, uint n, uint off)
{
    uint b0 = (off + 0u < n) ? (uint)p[off + 0u] : 0u;
    uint b1 = (off + 1u < n) ? (uint)p[off + 1u] : 0u;
    uint b2 = (off + 2u < n) ? (uint)p[off + 2u] : 0u;
    uint b3 = (off + 3u < n) ? (uint)p[off + 3u] : 0u;
    return b0 | (b1 << 8u) | (b2 << 16u) | (b3 << 24u);
}

inline ulong read_u64_le_private(const uchar* p, uint n, uint off)
{
    ulong v = 0UL;
    for (uint i = 0u; i < 8u; ++i) {
        ulong b = (off + i < n) ? (ulong)p[off + i] : 0UL;
        v |= (b << (8u * i));
    }
    return v;
}

inline ulong read_u64_le_global(const __global uchar* p, uint n, uint off)
{
    ulong v = 0UL;
    for (uint i = 0u; i < 8u; ++i) {
        ulong b = (off + i < n) ? (ulong)p[off + i] : 0UL;
        v |= (b << (8u * i));
    }
    return v;
}

inline void write_u32_le_private(uchar* p, uint off, uint v)
{
    p[off + 0u] = (uchar)(v & 0xFFu);
    p[off + 1u] = (uchar)((v >> 8u) & 0xFFu);
    p[off + 2u] = (uchar)((v >> 16u) & 0xFFu);
    p[off + 3u] = (uchar)((v >> 24u) & 0xFFu);
}

inline void write_u32_le_global(__global uchar* p, uint off, uint v)
{
    p[off + 0u] = (uchar)(v & 0xFFu);
    p[off + 1u] = (uchar)((v >> 8u) & 0xFFu);
    p[off + 2u] = (uchar)((v >> 16u) & 0xFFu);
    p[off + 3u] = (uchar)((v >> 24u) & 0xFFu);
}

inline void write_u64_le_global(__global uchar* p, uint off, ulong v)
{
    for (uint i = 0u; i < 8u; ++i) {
        p[off + i] = (uchar)((v >> (8u * i)) & 0xFFUL);
    }
}

inline ulong splitmix64_step(__private ulong* x)
{
    *x += 0x9e3779b97f4a7c15UL;
    ulong z = *x;
    z = (z ^ (z >> 30u)) * 0xbf58476d1ce4e5b9UL;
    z = (z ^ (z >> 27u)) * 0x94d049bb133111ebUL;
    return z ^ (z >> 31u);
}

inline void keccakf1600(__private ulong st[25])
{
    __private ulong bc[5];

    for (uint round = 0u; round < 24u; ++round) {
        for (uint i = 0u; i < 5u; ++i) {
            bc[i] = st[i] ^ st[i + 5u] ^ st[i + 10u] ^ st[i + 15u] ^ st[i + 20u];
        }

        for (uint i = 0u; i < 5u; ++i) {
            ulong t = bc[(i + 4u) % 5u] ^ rotl64(bc[(i + 1u) % 5u], 1u);
            st[i]      ^= t;
            st[i + 5u] ^= t;
            st[i + 10u]^= t;
            st[i + 15u]^= t;
            st[i + 20u]^= t;
        }

        ulong t = st[1];
        for (uint i = 0u; i < 24u; ++i) {
            uint j = KECCAKF_PILN[i];
            ulong tmp = st[j];
            st[j] = rotl64(t, KECCAKF_ROTC[i]);
            t = tmp;
        }

        for (uint j = 0u; j < 25u; j += 5u) {
            ulong s0 = st[j + 0u];
            ulong s1 = st[j + 1u];
            ulong s2 = st[j + 2u];
            ulong s3 = st[j + 3u];
            ulong s4 = st[j + 4u];

            st[j + 0u] = s0 ^ ((~s1) & s2);
            st[j + 1u] = s1 ^ ((~s2) & s3);
            st[j + 2u] = s2 ^ ((~s3) & s4);
            st[j + 3u] = s3 ^ ((~s4) & s0);
            st[j + 4u] = s4 ^ ((~s0) & s1);
        }

        st[0] ^= KECCAKF_RNDC[round];
    }
}

inline void absorb_block(__private ulong st[25], const uchar* data, uint len)
{
    for (uint lane = 0u; lane < RX_RATE_LANES; ++lane) {
        st[lane] ^= read_u64_le_private(data, len, lane * 8u);
    }
    keccakf1600(st);
}

inline void absorb_padded(__private ulong st[25], const uchar* data, uint len, uchar domain)
{
    uchar block[RX_RATE_BYTES];
    for (uint i = 0u; i < RX_RATE_BYTES; ++i) {
        block[i] = 0;
    }
    for (uint i = 0u; i < len; ++i) {
        block[i] = data[i];
    }
    block[len] ^= domain;
    block[RX_RATE_BYTES - 1u] ^= (uchar)0x80u;
    absorb_block(st, block, RX_RATE_BYTES);
}

inline void absorb_blob_state(__private ulong st[25], const uchar* local_blob, uint blob_len)
{
    uint off = 0u;
    while ((off + RX_RATE_BYTES) <= blob_len) {
        for (uint lane = 0u; lane < RX_RATE_LANES; ++lane) {
            st[lane] ^= read_u64_le_private(local_blob, blob_len, off + lane * 8u);
        }
        keccakf1600(st);
        off += RX_RATE_BYTES;
    }

    uchar tail[RX_RATE_BYTES];
    uint rem = blob_len - off;
    for (uint i = 0u; i < RX_RATE_BYTES; ++i) {
        tail[i] = 0;
    }
    for (uint i = 0u; i < rem; ++i) {
        tail[i] = local_blob[off + i];
    }
    tail[rem] ^= (uchar)0x01u;
    tail[RX_RATE_BYTES - 1u] ^= (uchar)0x80u;
    absorb_block(st, tail, RX_RATE_BYTES);
}

inline ulong sample_window_mix(__global const uchar* src, uint src_len, uint src_off, uint bytes_to_mix)
{
    ulong acc = 0x243f6a8885a308d3UL ^ ((ulong)src_off << 17u) ^ (ulong)bytes_to_mix;
    for (uint i = 0u; i < bytes_to_mix; i += 8u) {
        ulong lane = read_u64_le_global(src, src_len, src_off + i);
        acc ^= rotl64(lane + 0x9e3779b97f4a7c15UL + (ulong)i, (uint)((i >> 1u) & 63u));
        acc = rotl64(acc, 11u) * 0xbf58476d1ce4e5b9UL;
    }
    return acc;
}

inline int better_candidate(ulong s0, ulong s1, ulong b0, ulong b1)
{
    if (s0 < b0) return 1;
    if (s0 > b0) return 0;
    return (s1 < b1) ? 1 : 0;
}

inline void insert_topk(
    ulong score0, ulong score1, uint nonce, ulong d0, ulong d1, ulong d2, ulong d3,
    __private ulong best_score0[RX_TOPK],
    __private ulong best_score1[RX_TOPK],
    __private uint  best_nonce[RX_TOPK],
    __private ulong best_d0[RX_TOPK],
    __private ulong best_d1[RX_TOPK],
    __private ulong best_d2[RX_TOPK],
    __private ulong best_d3[RX_TOPK])
{
    if (!better_candidate(score0, score1, best_score0[RX_TOPK - 1u], best_score1[RX_TOPK - 1u])) {
        return;
    }

    int pos = (int)RX_TOPK - 1;
    while (pos > 0 && better_candidate(score0, score1, best_score0[pos - 1], best_score1[pos - 1])) {
        best_score0[pos] = best_score0[pos - 1];
        best_score1[pos] = best_score1[pos - 1];
        best_nonce[pos]  = best_nonce[pos - 1];
        best_d0[pos]     = best_d0[pos - 1];
        best_d1[pos]     = best_d1[pos - 1];
        best_d2[pos]     = best_d2[pos - 1];
        best_d3[pos]     = best_d3[pos - 1];
        --pos;
    }

    best_score0[pos] = score0;
    best_score1[pos] = score1;
    best_nonce[pos]  = nonce;
    best_d0[pos]     = d0;
    best_d1[pos]     = d1;
    best_d2[pos]     = d2;
    best_d3[pos]     = d3;
}

__kernel void monero_scan(
    __global const uchar* seed_hash,
    __global const uchar* blob,
    uint blob_len,
    uint nonce_offset,
    uint start_nonce,
    uint target_lo,
    uint target_hi,
    uint max_results,
    __global uint* out_count,
    __global uchar* out_records,
    __global const uchar* randomx_cache,
    uint randomx_cache_bytes,
    __global const uchar* randomx_dataset,
    uint randomx_dataset_bytes,
    __global const uchar* randomx_vm_descriptor,
    uint randomx_vm_descriptor_bytes
)
{
    const uint gid = (uint)get_global_id(0);
    const uint lid = (uint)get_local_id(0);
    const uint local_n = (uint)get_local_size(0);
    const uint scan_n = (local_n < RX_LOCAL_MAX) ? local_n : RX_LOCAL_MAX;
    const uint nonce = start_nonce + gid;
    const ulong target64 = ((ulong)target_hi << 32) | (ulong)target_lo;

    __local ulong local_score0[RX_LOCAL_MAX];
    __local ulong local_score1[RX_LOCAL_MAX];
    __local uint  local_nonce[RX_LOCAL_MAX];
    __local ulong local_d0[RX_LOCAL_MAX];
    __local ulong local_d1[RX_LOCAL_MAX];
    __local ulong local_d2[RX_LOCAL_MAX];
    __local ulong local_d3[RX_LOCAL_MAX];

    ulong cand_score0 = 0xffffffffffffffffUL;
    ulong cand_score1 = 0xffffffffffffffffUL;
    ulong d0 = 0UL, d1 = 0UL, d2 = 0UL, d3 = 0UL;

    if (blob_len != 0u && blob_len <= RX_MAX_BLOB && (nonce_offset + 4u) <= blob_len) {
        uchar local_blob[RX_MAX_BLOB];
        for (uint i = 0u; i < blob_len; ++i) {
            local_blob[i] = blob[i];
        }
        write_u32_le_private(local_blob, nonce_offset, nonce);

        __private ulong st[25];
        for (uint i = 0u; i < 25u; ++i) {
            st[i] = 0UL;
        }

        st[0] = read_u64_le_global(seed_hash, 32u, 0u)  ^ 0x6a09e667f3bcc909UL;
        st[1] = read_u64_le_global(seed_hash, 32u, 8u)  ^ 0xbb67ae8584caa73bUL;
        st[2] = read_u64_le_global(seed_hash, 32u, 16u) ^ 0x3c6ef372fe94f82bUL;
        st[3] = read_u64_le_global(seed_hash, 32u, 24u) ^ 0xa54ff53a5f1d36f1UL;
        st[4] = ((ulong)nonce << 32) ^ (ulong)blob_len ^ 0x510e527fade682d1UL;
        st[5] = ((ulong)nonce_offset << 32) ^ (ulong)gid ^ 0x9b05688c2b3e6c1fUL;
        st[6] = target64 ^ 0x1f83d9abfb41bd6bUL;
        st[7] = rotl64(st[0] + st[2] + st[4], 17u);
        st[8] = rotl64(st[1] + st[3] + st[5], 29u);
        keccakf1600(st);

        absorb_blob_state(st, local_blob, blob_len);

        ulong rng = st[0] ^ rotl64(st[1], 7u) ^ rotl64(st[2], 19u) ^ rotl64(st[3], 31u);
        rng ^= ((ulong)nonce << 1u) ^ ((ulong)gid << 33u);

        if (randomx_cache_bytes >= RX_SAMPLE_BYTES) {
            for (uint i = 0u; i < RX_CACHE_SAMPLE_COUNT; ++i) {
                ulong r = splitmix64_step(&rng);
                uint span = randomx_cache_bytes - RX_SAMPLE_BYTES;
                uint off = (span > 0u) ? (uint)(r % (ulong)span) : 0u;

                uchar local_block[RX_RATE_BYTES];
                for (uint j = 0u; j < RX_RATE_BYTES; ++j) {
                    local_block[j] = 0;
                }
                for (uint j = 0u; j < RX_SAMPLE_BYTES; ++j) {
                    local_block[j] = randomx_cache[off + j];
                }

                ulong mixv = sample_window_mix(randomx_cache, randomx_cache_bytes, off, RX_SAMPLE_BYTES);
                write_u32_le_private(local_block, 96u, off);
                write_u32_le_private(local_block, 100u, RX_SAMPLE_BYTES);
                for (uint b = 0u; b < 8u; ++b) {
                    local_block[104u + b] = (uchar)((mixv >> (8u * b)) & 0xFFUL);
                }
                for (uint b = 0u; b < 8u; ++b) {
                    local_block[112u + b] = (uchar)((r >> (8u * b)) & 0xFFUL);
                }
                absorb_padded(st, local_block, 120u, (uchar)(0x20u + i));
            }
        }

        if (randomx_dataset_bytes >= RX_SAMPLE_BYTES) {
            for (uint i = 0u; i < RX_DATASET_SAMPLE_COUNT; ++i) {
                ulong r = splitmix64_step(&rng) ^ st[(i + 7u) % 25u];
                uint span = randomx_dataset_bytes - RX_SAMPLE_BYTES;
                uint off = (span > 0u) ? (uint)(r % (ulong)span) : 0u;

                uchar local_block[RX_RATE_BYTES];
                for (uint j = 0u; j < RX_RATE_BYTES; ++j) {
                    local_block[j] = 0;
                }
                for (uint j = 0u; j < RX_SAMPLE_BYTES; ++j) {
                    local_block[j] = randomx_dataset[off + j];
                }

                ulong mixv = sample_window_mix(randomx_dataset, randomx_dataset_bytes, off, RX_SAMPLE_BYTES);
                write_u32_le_private(local_block, 96u, off);
                write_u32_le_private(local_block, 100u, RX_SAMPLE_BYTES);
                for (uint b = 0u; b < 8u; ++b) {
                    local_block[104u + b] = (uchar)((mixv >> (8u * b)) & 0xFFUL);
                }
                for (uint b = 0u; b < 8u; ++b) {
                    local_block[112u + b] = (uchar)((r >> (8u * b)) & 0xFFUL);
                }
                absorb_padded(st, local_block, 120u, (uchar)(0x40u + i));
            }
        }

        if (randomx_vm_descriptor_bytes > 0u) {
            uint vm_take = randomx_vm_descriptor_bytes;
            if (vm_take > RX_VM_SAMPLE_BYTES) {
                vm_take = RX_VM_SAMPLE_BYTES;
            }

            uchar vm_block[RX_RATE_BYTES];
            for (uint i = 0u; i < RX_RATE_BYTES; ++i) {
                vm_block[i] = 0;
            }
            for (uint i = 0u; i < vm_take; ++i) {
                vm_block[i] = randomx_vm_descriptor[i];
            }
            write_u32_le_private(vm_block, 120u, randomx_vm_descriptor_bytes);
            write_u32_le_private(vm_block, 124u, nonce);
            absorb_padded(st, vm_block, 128u, (uchar)0x60u);
        }

        for (uint i = 0u; i < RX_FINAL_PASSES; ++i) {
            st[9]  ^= rotl64(st[0] + st[4] + st[8], 7u);
            st[10] ^= rotl64(st[1] + st[5] + st[7], 13u);
            st[11] ^= rotl64(st[2] + st[6] + st[9], 29u);
            st[12] ^= rotl64(st[3] + st[7] + st[10], 43u);
            st[13] ^= rotl64(st[4] + st[8] + st[11], 53u);
            st[14] ^= rotl64(st[5] + st[9] + st[12], 17u);
            keccakf1600(st);
        }

        d0 = st[0] ^ rotl64(st[5], 11u) ^ rotl64(st[10], 23u) ^ rotl64(st[15], 37u);
        d1 = st[1] ^ rotl64(st[6], 17u) ^ rotl64(st[11], 31u) ^ rotl64(st[16], 41u);
        d2 = st[2] ^ rotl64(st[7], 19u) ^ rotl64(st[12], 43u) ^ rotl64(st[17], 47u);
        d3 = st[3] ^ rotl64(st[8], 27u) ^ rotl64(st[13], 53u) ^ rotl64(st[18], 59u);

        int pass = (d0 <= target64);

#if RX_STRICT_SCREEN
        if (pass && RX_SECONDARY_MASK_BITS > 0u) {
            ulong q = d1 ^ rotl64(d2, 9u) ^ rotl64(d3, 21u);
            ulong mask = (RX_SECONDARY_MASK_BITS >= 63u)
                ? 0x7fffffffffffffffUL
                : ((1UL << RX_SECONDARY_MASK_BITS) - 1UL);
            pass = ((q & mask) == 0UL);
        }
#endif

        if (pass) {
            cand_score0 = d0;
            cand_score1 = d1 ^ rotl64(d2, 13u) ^ rotl64(d3, 29u);
        }
    }

    if (lid < RX_LOCAL_MAX) {
        local_score0[lid] = cand_score0;
        local_score1[lid] = cand_score1;
        local_nonce[lid]  = nonce;
        local_d0[lid]     = d0;
        local_d1[lid]     = d1;
        local_d2[lid]     = d2;
        local_d3[lid]     = d3;
    }

    barrier(CLK_LOCAL_MEM_FENCE);

    if (lid == 0u) {
        __private ulong best_score0[RX_TOPK];
        __private ulong best_score1[RX_TOPK];
        __private uint  best_nonce[RX_TOPK];
        __private ulong best_d0[RX_TOPK];
        __private ulong best_d1[RX_TOPK];
        __private ulong best_d2[RX_TOPK];
        __private ulong best_d3[RX_TOPK];

        for (uint i = 0u; i < RX_TOPK; ++i) {
            best_score0[i] = 0xffffffffffffffffUL;
            best_score1[i] = 0xffffffffffffffffUL;
            best_nonce[i]  = 0u;
            best_d0[i]     = 0UL;
            best_d1[i]     = 0UL;
            best_d2[i]     = 0UL;
            best_d3[i]     = 0UL;
        }

        for (uint i = 0u; i < scan_n; ++i) {
            if (local_score0[i] == 0xffffffffffffffffUL) {
                continue;
            }
            insert_topk(
                local_score0[i], local_score1[i], local_nonce[i],
                local_d0[i], local_d1[i], local_d2[i], local_d3[i],
                best_score0, best_score1, best_nonce, best_d0, best_d1, best_d2, best_d3
            );
        }

        for (uint k = 0u; k < RX_TOPK; ++k) {
            if (best_score0[k] == 0xffffffffffffffffUL) {
                break;
            }
            if (best_d0[k] > target64) {
                continue;
            }

            uint slot = atomic_inc(out_count);
            if (slot >= max_results) {
                break;
            }

            const uint base = slot * 36u;
            write_u32_le_global(out_records, base + 0u, best_nonce[k]);
            write_u64_le_global(out_records, base + 4u,  best_d0[k]);
            write_u64_le_global(out_records, base + 12u, best_d1[k]);
            write_u64_le_global(out_records, base + 20u, best_d2[k]);
            write_u64_le_global(out_records, base + 28u, best_d3[k]);
        }
    }
}