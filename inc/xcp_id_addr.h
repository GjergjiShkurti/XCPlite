#pragma once
/* SPDX-License-Identifier: MIT */

//-----------------------------------------------------------------------------------------------
// Layout of the 32 bit address field under identifier (resolve-table) addressing.
//
// The identifier names the object; the low bits are a byte offset into it. Split for the same
// reason segment relative addressing splits it (XcpAddrEncodeSegIndex): a master does arithmetic
// on ECU_ADDRESS and the result has to keep meaning the same object. Element i of an array is
// ECU_ADDRESS + i*elemsize, and an object wider than one ODT entry is armed as chunks at
// ECU_ADDRESS + k*XCP_MAX_ODT_ENTRY_SIZE. With the whole word spent on a dense identifier
// counter, id+k was another object's identifier: such a request sampled an unrelated variable, or
// was refused as out of range, depending only on how many objects the application happened to
// have.
//
// 16/16: 65535 identifiers, 64 KiB per object -- the same ceiling xcplite already imposes on a
// calibration segment.
//
// ONE definition, in a header with no dependencies, because three parties have to agree on it and
// they do not all see the same headers: an application emitting these addresses sees only the
// public inc/xcplib.h, the server decoding them compiles against the private src/xcp_cfg.h, and
// the offline A2L generator (tools/xcpclient) mirrors it in Rust. It used to be written out twice
// behind a shared include guard, which made a double include safe and a divergence silent -- the
// guard meant whichever header was reached first won, so an edit to one copy was discarded rather
// than diagnosed. The Rust mirror still has to be kept by hand; mc-instrument's id_offset test
// asserts these values so the two cannot part company unnoticed.
//-----------------------------------------------------------------------------------------------

#include <stdint.h>

/// Bits of the address field spent on the byte offset into the object.
#define XCP_ID_OFFSET_BITS 16

/// Mask selecting the byte offset.
#define XCP_ID_OFFSET_MASK ((uint32_t)((1u << XCP_ID_OFFSET_BITS) - 1u))

/// The largest identifier the field can hold. Identifier 0 is reserved as invalid.
#define XCP_ID_MAX ((uint32_t)(0xFFFFFFFFu >> XCP_ID_OFFSET_BITS))

/// The most bytes one identifier can address, offset field inclusive.
#define XCP_ID_OBJECT_MAX_BYTES ((uint32_t)XCP_ID_OFFSET_MASK + 1u)

/// Pack an identifier and a byte offset into an ODT entry's address field.
#define XcpAddrEncodeId(id, offset) (uint32_t)((((uint32_t)(id)) << XCP_ID_OFFSET_BITS) | (((uint32_t)(offset)) & XCP_ID_OFFSET_MASK))

/// The identifier an address field names.
#define XcpAddrDecodeId(addr) (uint32_t)(((uint32_t)(addr)) >> XCP_ID_OFFSET_BITS)

/// The byte offset into the object an address field names.
#define XcpAddrDecodeIdOffset(addr) (uint32_t)(((uint32_t)(addr)) & XCP_ID_OFFSET_MASK)

//-----------------------------------------------------------------------------------------------
// The resolution table, and the addresses one trigger passes with it.
//
// Here for the same reason as the layout above: the application fills them and the server reads
// them, and the two do not see the same headers. The table entry used to be defined twice, in
// inc/xcplib.h and src/xcplite.h, behind one include guard.
//-----------------------------------------------------------------------------------------------

#define XCP_RESOLVE_SEG_NONE 0xFFFF

/// tXcpResolveEntry.flags: `event` names the only event that may sample the identifier. A DAQ
/// list that arms the identifier on any other event is refused when it starts (CRC_DAQ_CONFIG).
#define XCP_RESOLVE_FLAG_EVENT 0x0001u

/// One identifier's entry in the table published by XcpSetResolveTable(), which is indexed by the
/// identifier. Index 0 is reserved.
typedef struct {
    /// The object's live location as the last trigger stored it, or NULL if not currently available.
    ///
    /// Read by two consumers: ApplXcpReadMemory -- the callback registered through
    /// ApplXcpRegisterReadCallback, serving SHORT_UPLOAD / UPLOAD / CALC_CHECKSUM on the XCP
    /// command thread -- and the DAQ sampling loop, but only for a trigger that passes no addresses
    /// of its own (XcpEventExtAt_ and the other XcpEvent* calls). A trigger through XcpEventIdsAt_
    /// is sampled through the addresses it passes and never through this field.
    ///
    /// Written by the application per trigger, as a plain access. **One identifier must be updated
    /// from one thread:** with two writers, a reader may be handed either one's address. The value
    /// is never torn on a supported target (an aligned pointer), but the access is a data race by
    /// the standard, and a sanitizer will say so. Deliberately not an atomic: this struct is shared
    /// between C11 and C++17 translation units, so the field would be spelled differently on each
    /// side of the seam for no change in the observable outcome. The *table* is published
    /// atomically; see XcpSetResolveTable.
    void *ptr;
    uint32_t size;  ///< Byte size of the object: the bound for every access, at arm time and per sample
    uint16_t seg;   ///< Calibration segment index, or XCP_RESOLVE_SEG_NONE for a measurement
    uint16_t flags; ///< XCP_RESOLVE_FLAG_*
    uint16_t event; ///< The owning event, when flags has XCP_RESOLVE_FLAG_EVENT
} tXcpResolveEntry;

/// The addresses one trigger passes for its own objects, to XcpEventIdsAt_: ptrs[i] is the live
/// address of identifier first + i, or NULL. An identifier outside [first, first + count) is not
/// this trigger's, and is sampled as zero.
///
/// This is what makes a trigger's sample its own. The array lives in the caller's frame for the
/// duration of the call, so a second thread triggering the same event, or another event storing
/// the same identifier, cannot change what this trigger samples.
typedef struct tXcpIdBases {
    const void *const *ptrs;
    uint32_t first;
    uint32_t count;
} tXcpIdBases;
