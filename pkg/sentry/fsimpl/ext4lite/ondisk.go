// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ext4lite

import "encoding/binary"

// Geometry of every ext4lite volume. The values follow the GVXIP-002 profile
// of mkfs.ext4 -b 4096 -g 4096 -I 256 -N 4096 per group.
const (
	blockSize        = 4096
	blockShift       = 12
	blocksPerGroup   = 4096
	inodesPerGroup   = 4096
	inodeSize        = 256
	descSize         = 64
	descsPerBlock    = blockSize / descSize
	inodesPerBlock   = blockSize / inodeSize
	inodeTableBlocks = inodesPerGroup * inodeSize / blockSize
	groupBytes       = blocksPerGroup * blockSize

	// gdtAreaBlocks is the number of blocks behind the superblock that hold
	// the group descriptors and the reserved descriptor blocks. The sum stays
	// constant: a new descriptor block takes the first reserved block.
	gdtAreaBlocks = 64

	// maxGroups is the number of descriptors that the descriptor area holds.
	maxGroups = gdtAreaBlocks * descsPerBlock

	// maxVolumeBytes is the size limit of a volume.
	maxVolumeBytes = maxGroups * groupBytes

	// headerBlocks is the size of the superblock and the descriptor area.
	headerBlocks = 1 + gdtAreaBlocks

	superOffset = 1024
	superSize   = 1024
	superMagic  = 0xEF53

	firstIno  = 11
	rootIno   = 2
	resizeIno = 7

	// extraIsize is the size of the extra inode fields. The in-inode xattr
	// area starts behind them.
	extraIsize  = 32
	ibodyOffset = 128 + extraIsize
	ibodySize   = inodeSize - ibodyOffset

	// xattrMagic starts the in-inode xattr area and the xattr block.
	xattrMagic = 0xEA020000
)

// Feature flags of the profile.
const (
	compatExtAttr     = 0x0008
	compatResizeInode = 0x0010

	incompatFiletype   = 0x0002
	incompatExtents    = 0x0040
	incompat64bit      = 0x0080
	incompatInlineData = 0x8000

	roCompatSparseSuper = 0x0001
	roCompatLargeFile   = 0x0002
	roCompatExtraIsize  = 0x0040

	featCompat   = compatExtAttr | compatResizeInode
	featIncompat = incompatFiletype | incompatExtents | incompat64bit | incompatInlineData
	featRoCompat = roCompatSparseSuper | roCompatLargeFile | roCompatExtraIsize
)

// Superblock state bits.
const (
	stateValid = 0x0001
	stateError = 0x0002
)

// Inode flags.
const (
	flagExtents    = 0x00080000
	flagInlineData = 0x10000000
)

// Inode mode bits.
const (
	modeTypeMask = 0xF000
	modeSocket   = 0xC000
	modeSymlink  = 0xA000
	modeRegular  = 0x8000
	modeBlock    = 0x6000
	modeDir      = 0x4000
	modeChar     = 0x2000
	modeFIFO     = 0x1000
)

// Directory entry file types.
const (
	ftUnknown = 0
	ftRegular = 1
	ftDir     = 2
	ftChar    = 3
	ftBlock   = 4
	ftFIFO    = 5
	ftSocket  = 6
	ftSymlink = 7
)

// Offsets inside the 1024-byte superblock.
const (
	sbInodesCount     = 0x00
	sbBlocksCountLo   = 0x04
	sbRBlocksCountLo  = 0x08
	sbFreeBlocksLo    = 0x0C
	sbFreeInodes      = 0x10
	sbFirstDataBlock  = 0x14
	sbLogBlockSize    = 0x18
	sbLogClusterSize  = 0x1C
	sbBlocksPerGroup  = 0x20
	sbClustersPerGrp  = 0x24
	sbInodesPerGroup  = 0x28
	sbMtime           = 0x2C
	sbWtime           = 0x30
	sbMntCount        = 0x34
	sbMaxMntCount     = 0x36
	sbMagic           = 0x38
	sbState           = 0x3A
	sbErrors          = 0x3C
	sbMinorRev        = 0x3E
	sbLastCheck       = 0x40
	sbCheckInterval   = 0x44
	sbCreatorOS       = 0x48
	sbRevLevel        = 0x4C
	sbFirstIno        = 0x54
	sbInodeSize       = 0x58
	sbBlockGroupNr    = 0x5A
	sbFeatureCompat   = 0x5C
	sbFeatureIncompat = 0x60
	sbFeatureRoCompat = 0x64
	sbUUID            = 0x68
	sbVolumeName      = 0x78
	sbReservedGDT     = 0xCE
	sbHashSeed        = 0xEC
	sbDefHashVersion  = 0xFC
	sbDescSize        = 0xFE
	sbDefaultMountOpt = 0x100
	sbMkfsTime        = 0x108
	sbBlocksCountHi   = 0x150
	sbRBlocksCountHi  = 0x154
	sbFreeBlocksHi    = 0x158
	sbMinExtraIsize   = 0x15C
	sbWantExtraIsize  = 0x15E
	sbFlags           = 0x160
)

// Offsets inside a 64-byte group descriptor.
const (
	gdBlockBitmapLo  = 0x00
	gdInodeBitmapLo  = 0x04
	gdInodeTableLo   = 0x08
	gdFreeBlocksLo   = 0x0C
	gdFreeInodesLo   = 0x0E
	gdUsedDirsLo     = 0x10
	gdFlags          = 0x12
	gdItableUnusedLo = 0x1C
	gdBlockBitmapHi  = 0x20
	gdInodeBitmapHi  = 0x24
	gdInodeTableHi   = 0x28
	gdFreeBlocksHi   = 0x2C
	gdFreeInodesHi   = 0x2E
	gdUsedDirsHi     = 0x30
)

// Offsets inside a 256-byte inode.
const (
	inMode      = 0x00
	inUID       = 0x02
	inSizeLo    = 0x04
	inAtime     = 0x08
	inCtime     = 0x0C
	inMtime     = 0x10
	inDtime     = 0x14
	inGID       = 0x18
	inLinks     = 0x1A
	inBlocksLo  = 0x1C
	inFlags     = 0x20
	inBlock     = 0x28
	inGen       = 0x64
	inFileACLLo = 0x68
	inSizeHi    = 0x6C
	inBlocksHi  = 0x74
	inFileACLHi = 0x76
	inUIDHi     = 0x78
	inGIDHi     = 0x7A
	inExtraSize = 0x80
	inCtimeEx   = 0x84
	inMtimeEx   = 0x88
	inAtimeEx   = 0x8C
	inCrtime    = 0x90
	inCrtimeEx  = 0x94

	// iBlockSize is the size of i_block in bytes.
	iBlockSize = 60
)

var le = binary.LittleEndian

// groupDesc is the parsed group descriptor of one block group.
type groupDesc struct {
	blockBitmap uint64
	inodeBitmap uint64
	inodeTable  uint64
	freeBlocks  uint32
	freeInodes  uint32
	usedDirs    uint32
}

func (g *groupDesc) encode(b []byte) {
	clear(b[:descSize])
	le.PutUint32(b[gdBlockBitmapLo:], uint32(g.blockBitmap))
	le.PutUint32(b[gdInodeBitmapLo:], uint32(g.inodeBitmap))
	le.PutUint32(b[gdInodeTableLo:], uint32(g.inodeTable))
	le.PutUint16(b[gdFreeBlocksLo:], uint16(g.freeBlocks))
	le.PutUint16(b[gdFreeInodesLo:], uint16(g.freeInodes))
	le.PutUint16(b[gdUsedDirsLo:], uint16(g.usedDirs))
	le.PutUint32(b[gdBlockBitmapHi:], uint32(g.blockBitmap>>32))
	le.PutUint32(b[gdInodeBitmapHi:], uint32(g.inodeBitmap>>32))
	le.PutUint32(b[gdInodeTableHi:], uint32(g.inodeTable>>32))
	le.PutUint16(b[gdFreeBlocksHi:], uint16(g.freeBlocks>>16))
	le.PutUint16(b[gdFreeInodesHi:], uint16(g.freeInodes>>16))
	le.PutUint16(b[gdUsedDirsHi:], uint16(g.usedDirs>>16))
}

func (g *groupDesc) decode(b []byte) {
	g.blockBitmap = uint64(le.Uint32(b[gdBlockBitmapLo:])) | uint64(le.Uint32(b[gdBlockBitmapHi:]))<<32
	g.inodeBitmap = uint64(le.Uint32(b[gdInodeBitmapLo:])) | uint64(le.Uint32(b[gdInodeBitmapHi:]))<<32
	g.inodeTable = uint64(le.Uint32(b[gdInodeTableLo:])) | uint64(le.Uint32(b[gdInodeTableHi:]))<<32
	g.freeBlocks = uint32(le.Uint16(b[gdFreeBlocksLo:])) | uint32(le.Uint16(b[gdFreeBlocksHi:]))<<16
	g.freeInodes = uint32(le.Uint16(b[gdFreeInodesLo:])) | uint32(le.Uint16(b[gdFreeInodesHi:]))<<16
	g.usedDirs = uint32(le.Uint16(b[gdUsedDirsLo:])) | uint32(le.Uint16(b[gdUsedDirsHi:]))<<16
}

// extent is one run of file blocks. A file block is a logical 4 KiB block.
type extent struct {
	lblk uint32
	n    uint32 // 1 to maxExtentLen, or to maxUninitExtentLen when uninit
	pblk uint64
	// uninit marks an extent whose blocks read as zeros until a write sets them.
	uninit bool
}

// Extent tree limits.
const (
	extMagic        = 0xF30A
	maxExtentLen    = 32768
	rootExtents     = 4
	leafExtents     = (blockSize - 12) / 12
	extHeaderSize   = 12
	extEntrySize    = 12
	maxLogicalBlock = 1<<32 - 1
)

func (e extent) end() uint32         { return e.lblk + e.n }
func (e extent) pend() uint64        { return e.pblk + uint64(e.n) }
func (e extent) pbn(l uint32) uint64 { return e.pblk + uint64(l-e.lblk) }

// encodeExtentHeader writes an extent header.
func encodeExtentHeader(b []byte, entries, max, depth int) {
	le.PutUint16(b[0:], extMagic)
	le.PutUint16(b[2:], uint16(entries))
	le.PutUint16(b[4:], uint16(max))
	le.PutUint16(b[6:], uint16(depth))
	le.PutUint32(b[8:], 0)
}

func encodeExtent(b []byte, e extent) {
	le.PutUint32(b[0:], e.lblk)
	ln := uint16(e.n)
	if e.uninit {
		ln += uninitExtentOffset
	}
	le.PutUint16(b[4:], ln)
	le.PutUint16(b[6:], uint16(e.pblk>>32))
	le.PutUint32(b[8:], uint32(e.pblk))
}

// decodeExtent reads an extent entry. An ee_len above maxExtentLen marks an
// uninitialized extent whose length is ee_len minus maxExtentLen.
func decodeExtent(b []byte) extent {
	ln := le.Uint16(b[4:])
	e := extent{
		lblk: le.Uint32(b[0:]),
		pblk: uint64(le.Uint16(b[6:]))<<32 | uint64(le.Uint32(b[8:])),
	}
	if ln > maxExtentLen {
		e.uninit = true
		ln -= uninitExtentOffset
	}
	e.n = uint32(ln)
	return e
}

func encodeExtentIdx(b []byte, lblk uint32, leaf uint64) {
	le.PutUint32(b[0:], lblk)
	le.PutUint32(b[4:], uint32(leaf))
	le.PutUint16(b[8:], uint16(leaf>>32))
	le.PutUint16(b[10:], 0)
}

func decodeExtentIdx(b []byte) (lblk uint32, leaf uint64) {
	return le.Uint32(b[0:]), uint64(le.Uint16(b[8:]))<<32 | uint64(le.Uint32(b[4:]))
}

// roundUp4 rounds n up to a multiple of four.
func roundUp4(n int) int { return (n + 3) &^ 3 }
