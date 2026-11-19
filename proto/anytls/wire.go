package anytls

import (
	"encoding/binary"
	"strings"
)

const (
	opWaste          = 0
	opSyn            = 1
	opPush           = 2
	opFin            = 3
	opSettings       = 4
	opAlert          = 5
	opScheme         = 6
	opSynAck         = 7
	opBeat           = 8
	opBeatAck        = 9
	opServerSettings = 10

	headLen = 7
	maxBody = 0xFFFF

	protoVersion = 2
	clientName   = "kami/0.1"
)

func appendFrame(dst []byte, op byte, sid uint32, body []byte) []byte {
	dst = append(dst, op)
	dst = binary.BigEndian.AppendUint32(dst, sid)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))
	return append(dst, body...)
}

func wasteFrame(total int) []byte {
	total = max(total, headLen)
	out := make([]byte, total)
	out[0] = opWaste
	binary.BigEndian.PutUint16(out[5:], uint16(total-headLen))
	return out
}

func encodeKV(pairs ...string) []byte {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(pairs[i])
		b.WriteByte('=')
		b.WriteString(pairs[i+1])
	}
	return []byte(b.String())
}

func decodeKV(raw []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}
