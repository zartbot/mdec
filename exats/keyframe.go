package exats

import (
	"encoding/binary"
	"fmt"
)

type RefClock struct {
	Timestamp int64
	TickCnt   uint64
	Frequency uint64
	LastSync  uint64
}

func DecodeKeyFrame(data []byte) (*RefClock, error) {
	if len(data) <= 40 {
		return nil, fmt.Errorf("invalid length")
	}

	//check magic number
	if binary.LittleEndian.Uint32(data[0:4]) != 0x464b5845 {
		return nil, fmt.Errorf("invalid magic number")

	}

	r := &RefClock{
		Timestamp: int64(binary.BigEndian.Uint64(data[8:16])),
		Frequency: binary.BigEndian.Uint64(data[24:32]),
		LastSync:  binary.BigEndian.Uint64(data[32:40]),
	}
	r.TickCnt = binary.BigEndian.Uint64(data[16:24]) & 0xffffffff

	return r, nil
}
