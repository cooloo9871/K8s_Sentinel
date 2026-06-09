package k8s

// Hand-rolled protobuf decoder for Tetragon's DumpProcessCache response.
// Avoids adding github.com/cilium/tetragon as a full module dependency.
//
// Relevant Tetragon proto fields:
//   ProcessCacheList { repeated ProcessInternal processes = 1; }
//   ProcessInternal  { Process process = 1; }
//   Process          { string binary = 5; Pod pod = 10; }
//   Pod              { string namespace = 1; string name = 2; }

type processEntry struct{ namespace, pod, binary string }

func decodeProcessCacheList(data []byte) []processEntry {
	var result []processEntry
	for i := 0; i < len(data); {
		fn, wt, n := protoTag(data, i)
		i += n
		if n == 0 {
			break
		}
		if wt == 2 && fn == 1 {
			l, n2 := protoVarint(data, i)
			i += n2
			if n2 == 0 || i+int(l) > len(data) {
				break
			}
			if e := decodeProcessInternal(data[i : i+int(l)]); e.binary != "" {
				result = append(result, e)
			}
			i += int(l)
		} else {
			i += protoSkip(data, i, wt)
		}
	}
	return result
}

func decodeProcessInternal(data []byte) processEntry {
	for i := 0; i < len(data); {
		fn, wt, n := protoTag(data, i)
		i += n
		if n == 0 {
			break
		}
		if wt == 2 && fn == 1 {
			l, n2 := protoVarint(data, i)
			i += n2
			if n2 == 0 || i+int(l) > len(data) {
				break
			}
			return decodeProcess(data[i : i+int(l)])
		}
		i += protoSkip(data, i, wt)
	}
	return processEntry{}
}

func decodeProcess(data []byte) processEntry {
	var e processEntry
	for i := 0; i < len(data); {
		fn, wt, n := protoTag(data, i)
		i += n
		if n == 0 {
			break
		}
		if wt == 2 {
			l, n2 := protoVarint(data, i)
			i += n2
			if n2 == 0 || i+int(l) > len(data) {
				break
			}
			switch fn {
			case 5:
				e.binary = string(data[i : i+int(l)])
			case 10:
				e.namespace, e.pod = decodePod(data[i : i+int(l)])
			}
			i += int(l)
		} else {
			i += protoSkip(data, i, wt)
		}
	}
	return e
}

func decodePod(data []byte) (namespace, name string) {
	for i := 0; i < len(data); {
		fn, wt, n := protoTag(data, i)
		i += n
		if n == 0 {
			break
		}
		if wt == 2 {
			l, n2 := protoVarint(data, i)
			i += n2
			if n2 == 0 || i+int(l) > len(data) {
				break
			}
			switch fn {
			case 1:
				namespace = string(data[i : i+int(l)])
			case 2:
				name = string(data[i : i+int(l)])
			}
			i += int(l)
		} else {
			i += protoSkip(data, i, wt)
		}
	}
	return
}

func protoTag(data []byte, off int) (fieldNum, wireType uint64, n int) {
	v, n := protoVarint(data, off)
	return v >> 3, v & 7, n
}

func protoVarint(data []byte, off int) (uint64, int) {
	var x uint64
	for s := uint(0); off < len(data); s += 7 {
		b := data[off]
		off++
		x |= uint64(b&0x7f) << s
		if b < 0x80 {
			return x, int(s/7) + 1
		}
	}
	return 0, 0
}

func protoSkip(data []byte, off int, wireType uint64) int {
	switch wireType {
	case 0:
		_, n := protoVarint(data, off)
		return n
	case 1:
		return 8
	case 2:
		l, n := protoVarint(data, off)
		return n + int(l)
	case 5:
		return 4
	}
	return len(data) - off
}
