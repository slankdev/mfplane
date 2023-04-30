package util

func BS16(v uint16) uint16 {
	v2 := uint16(0)
	v2 |= v<<8 | v>>8
	return v2
}

func BS32(v uint32) uint32 {
	v2 := uint32(0)
	v2 |= (0xff000000 & (v << 24)) | (0x00ff0000 & (v << 8)) | (0x0000ff00 & (v >> 8)) | (0x000000ff & (v >> 24))
	return v2
}

func Uint32toBytes(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

func BitShiftLeft8(u8 [16]uint8) [16]uint8 {
	ret := [16]uint8{}
	for i := 0; i <= 15; i++ {
		if i == 15 {
			ret[i] = 0
		} else {
			ret[i] = u8[i+1]
		}
	}
	return ret
}

func BitShiftRight8(u8 [16]uint8) [16]uint8 {
	ret := [16]uint8{}
	for i := 15; i >= 0; i-- {
		if i == 0 {
			ret[i] = 0
		} else {
			ret[i] = u8[i-1]
		}
	}
	return ret
}
