/*
 * Copyright 2017-2018 Dgraph Labs, Inc. and Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bulk

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v2"
	bo "github.com/dgraph-io/badger/v2/options"
	bpb "github.com/dgraph-io/badger/v2/pb"
	"github.com/dgraph-io/badger/v2/y"
	"github.com/dgraph-io/dgraph/codec"
	"github.com/dgraph-io/dgraph/ee/enc"
	"github.com/dgraph-io/dgraph/posting"
	"github.com/dgraph-io/dgraph/protos/pb"
	"github.com/dgraph-io/dgraph/worker"
	"github.com/dgraph-io/dgraph/x"
)

type reducer struct {
	*state
	streamId uint32

	entrylistPool *sync.Pool
	mu            *sync.RWMutex
	streamIds     map[string]uint32
}

const batchSize = 10000
const batchAlloc = batchSize * 11 / 10

func (r *reducer) run() error {
	dirs := readShardDirs(filepath.Join(r.opt.TmpDir, reduceShardDir))
	x.AssertTrue(len(dirs) == r.opt.ReduceShards)
	x.AssertTrue(len(r.opt.shardOutputDirs) == r.opt.ReduceShards)

	thr := y.NewThrottle(r.opt.NumReducers)
	for i := 0; i < r.opt.ReduceShards; i++ {
		if err := thr.Do(); err != nil {
			return err
		}
		go func(shardId int, db *badger.DB) {
			defer thr.Done(nil)

			mapFiles := filenamesInTree(dirs[shardId])
			var mapItrs []*mapIterator
			partitionKeys := []*pb.MapEntry{}
			for _, mapFile := range mapFiles {
				header, itr := r.newMapIterator(mapFile)
				partitionKeys = append(partitionKeys, header.PartitionKeys...)
				mapItrs = append(mapItrs, itr)
			}

			writer := db.NewStreamWriter()
			if err := writer.Prepare(); err != nil {
				x.Check(err)
			}

			ci := &countIndexer{reducer: r, writer: writer}
			sort.Slice(partitionKeys, func(i, j int) bool {
				return bytes.Compare(partitionKeys[i].GetKey(), partitionKeys[j].GetKey()) < 0
			})

			// remove duplicate
			result := []*pb.MapEntry{}

			for _, entry := range partitionKeys {
				if len(result) == 0 {
					result = append(result, entry)
					continue
				}
				if bytes.Equal(result[len(result)-1].GetKey(), entry.Key) {
					continue
				}
				result = append(result, entry)
			}
			sort.Slice(result, func(i, j int) bool {
				return bytes.Compare(result[i].GetKey(), result[j].GetKey()) < 0
			})

			// Start bactching for the given keys
			fmt.Printf("Num map iterators: %d\n", len(mapItrs))
			for _, itr := range mapItrs {
				go itr.startBatchingForKeys(result)
			}
			r.reduce(result, mapItrs, ci)
			ci.wait()

			if err := writer.Flush(); err != nil {
				x.Check(err)
			}
			for _, itr := range mapItrs {
				if err := itr.Close(); err != nil {
					fmt.Printf("Error while closing iterator: %v", err)
				}
			}
		}(i, r.createBadger(i))
	}
	return thr.Finish()
}

func (r *reducer) createBadger(i int) *badger.DB {
	if r.opt.BadgerKeyFile != "" {
		// need to set zero addr in WorkerConfig before doing license check.
		x.WorkerConfig.ZeroAddr = r.opt.ZeroAddr
		// non-nil key file
		if !worker.EnterpriseEnabled() {
			// not licensed --> crash.
			log.Fatal("Enterprise License needed for the Encryption feature.")
		} else {
			// licensed --> OK.
			log.Printf("Encryption feature enabled. Using encryption key file: %v", r.opt.BadgerKeyFile)
		}
	}

	opt := badger.DefaultOptions(r.opt.shardOutputDirs[i]).WithSyncWrites(false).
		WithTableLoadingMode(bo.MemoryMap).WithValueThreshold(1 << 10 /* 1 KB */).
		WithLogger(nil).WithMaxCacheSize(1 << 20).
		WithEncryptionKey(enc.ReadEncryptionKeyFile(r.opt.BadgerKeyFile)).WithCompression(bo.None)

	// TOOD(Ibrahim): Remove this once badger is updated.
	opt.ZSTDCompressionLevel = 1

	db, err := badger.OpenManaged(opt)
	x.Check(err)

	// zero out the key from memory.
	opt.EncryptionKey = nil

	r.dbs = append(r.dbs, db)
	return db
}

// var allocator *MemAllocator

// var allocatorLock sync.Mutex

// func init() {
// 	allocator = NewAllocator()
// }

// func ResetAllocator() {
// 	done := atomic.LoadUint64(&allocator.done)
// 	if done != 1 {
// 		return
// 	}
// 	allocatorLock.Lock()
// 	defer allocatorLock.Unlock()
// 	done = atomic.LoadUint64(&allocator.done)
// 	if done != 1 {
// 		return
// 	}
// 	// Some reset allocator have made the new allocation so move forward
// 	allocator = NewAllocator()
// }

// type MemAllocator struct {
// 	sync.Mutex
// 	index int
// 	data  []byte
// }

// func NewAllocator() *MemAllocator {
// 	return &MemAllocator{
// 		index: 0,
// 		data:  make([]byte, 64*1024*1024),
// 	}
// }

// func (m *MemAllocator) Allocate(n int) []byte {
// 	if n > 64*1024*1024 {
// 		return make([]byte, n)
// 	}
// 	m.Lock()
// 	defer m.Unlock()
// 	if m.index+n > len(m.data) {
// 		m.data = make([]byte, 64*1024*1024)
// 		m.index = 0
// 	}
// 	eBuf := m.data[m.index : m.index+n]
// 	m.index += n
// 	return eBuf
// }

type mapIterator struct {
	fd            *os.File
	reader        *bufio.Reader
	tmpBuf        []byte
	current       *iteratorEntry
	batchCh       chan *iteratorEntry
	freelist      chan *iteratorEntry
	entrylistPool *sync.Pool
}

type iteratorEntry struct {
	partitionKey *pb.MapEntry
	batch        [][]byte
}

func (mi *mapIterator) release(ie *iteratorEntry) {
	ie.batch = ie.batch[:0]
	select {
	case mi.freelist <- ie:
	default:
	}
}

func (mi *mapIterator) startBatchingForKeys(partitionsKeys []*pb.MapEntry) {
	i := 1
	var bufStartIndex int
	var ie *iteratorEntry
	prevKeyExist := false
	var buf, eBuf, key []byte
	var err error
	for _, pKey := range partitionsKeys {
		select {
		case ie = <-mi.freelist:
		default:
			ie = &iteratorEntry{
				batch: make([][]byte, 0, batchAlloc),
			}
		}
		ie.partitionKey = pKey

		for {
			if !prevKeyExist {
				r := mi.reader
				buf, err = r.Peek(binary.MaxVarintLen64)
				if err == io.EOF {
					break
				}
				x.Check(err)
				sz, n := binary.Uvarint(buf)
				if n <= 0 {
					log.Fatalf("Could not read uvarint: %d", n)
				}
				x.Check2(r.Discard(n))

				eBuf = make([]byte, sz)
				x.Check2(io.ReadFull(r, eBuf))

				key, err = GetKeyForMapEntry(eBuf)
				x.Check(err)
			}
			if bytes.Compare(key, ie.partitionKey.GetKey()) < 0 {
				prevKeyExist = false
				ie.batch = append(ie.batch, eBuf)
				continue
			}
			// present key is not part of this batch so, track that we have already read the key.
			prevKeyExist = true
			break
		}
		mi.batchCh <- ie
		i++
	}

	// Drain the last items.
	batch := make([][]byte, 0, batchAlloc)
	for {
		if !prevKeyExist {
			r := mi.reader
			buf, err = r.Peek(binary.MaxVarintLen64)
			if err == io.EOF {
				break
			}
			x.Check(err)
			sz, n := binary.Uvarint(buf)
			if n <= 0 {
				log.Fatalf("Could not read uvarint: %d", n)
			}
			x.Check2(r.Discard(n))

			eBuf = make([]byte, sz)
			bufStartIndex += int(sz)
			x.Check2(io.ReadFull(r, eBuf))
		}
		prevKeyExist = false
		batch = append(batch, eBuf)
	}
	mi.batchCh <- &iteratorEntry{
		batch:        batch,
		partitionKey: nil,
	}
}
func (mi *mapIterator) Close() error {
	return mi.fd.Close()
}

func (mi *mapIterator) Current() *iteratorEntry {
	return mi.current
}

func (mi *mapIterator) Next() bool {
	mi.current = <-mi.batchCh
	return true
}

func (r *reducer) newMapIterator(filename string) (*pb.MapperHeader, *mapIterator) {
	fd, err := os.Open(filename)
	x.Check(err)
	gzReader, err := gzip.NewReader(fd)
	x.Check(err)

	// Read the header size.
	reader := bufio.NewReaderSize(gzReader, 16<<10)
	headerLenBuf := make([]byte, 8)
	x.Check2(io.ReadFull(reader, headerLenBuf))
	headerLen := binary.BigEndian.Uint64(headerLenBuf)
	// Reader the map header.
	headerBuf := make([]byte, headerLen)

	x.Check2(io.ReadFull(reader, headerBuf))
	header := &pb.MapperHeader{}
	err = header.Unmarshal(headerBuf)
	x.Check(err)

	itr := &mapIterator{
		fd:            fd,
		reader:        reader,
		batchCh:       make(chan *iteratorEntry, 3),
		freelist:      make(chan *iteratorEntry, 3),
		entrylistPool: r.entrylistPool,
	}
	return header, itr
}

type countIndexEntry struct {
	key   []byte
	count int
}

type encodeRequest struct {
	entries   [][]byte
	countKeys []*countIndexEntry
	wg        *sync.WaitGroup
	list      *bpb.KVList
}

func (r *reducer) streamIdFor(pred string) uint32 {
	r.mu.RLock()
	if id, ok := r.streamIds[pred]; ok {
		r.mu.RUnlock()
		return id
	}
	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.streamIds[pred]; ok {
		return id
	}
	streamId := atomic.AddUint32(&r.streamId, 1)
	r.streamIds[pred] = streamId
	return streamId
}

func (r *reducer) encode(entryCh chan *encodeRequest, closer *y.Closer) {
	defer closer.Done()
	for req := range entryCh {

		req.list = &bpb.KVList{}
		countKeys := r.toList(req.entries, req.list)
		// r.toList(req) // contains entries, list and freelist struct.
		for _, kv := range req.list.Kv {
			pk, err := x.Parse(kv.Key)
			x.Check(err)
			x.AssertTrue(len(pk.Attr) > 0)
			kv.StreamId = r.streamIdFor(pk.Attr)
		}
		req.countKeys = countKeys
		req.wg.Done()
		atomic.AddInt32(&r.prog.numEncoding, -1)
	}
}

func (r *reducer) startWriting(ci *countIndexer, writerCh chan *encodeRequest, closer *y.Closer) {
	defer closer.Done()

	idx := 0
	for req := range writerCh {
		for _, countKey := range req.countKeys {
			ci.addUid(countKey.key, countKey.count)
		}
		// Wait for it to be encoded.
		start := time.Now()
		req.wg.Wait()

		ci.writer.Write(req.list)
		// writer.Write(listBatch[0].list)
		if dur := time.Since(start).Round(time.Millisecond); dur > time.Second {
			fmt.Printf("writeCh: Time taken to write req %d: %v\n", idx, time.Since(start).Round(time.Millisecond))
		}
		idx++
		if idx%100 == 0 {
			fmt.Printf("Wrote req: %d\n", idx)
		}
	}
}

func (r *reducer) encodeAndWrite_UNUSED(
	writer *badger.StreamWriter, entryCh chan []*pb.MapEntry, closer *y.Closer) {
	defer closer.Done()

	var listSize int
	list := &bpb.KVList{}

	preds := make(map[string]uint32)
	setStreamId := func(kv *bpb.KV) {
		pk, err := x.Parse(kv.Key)
		x.Check(err)
		x.AssertTrue(len(pk.Attr) > 0)

		// We don't need to consider the data prefix, count prefix, etc. because each predicate
		// contains sorted keys, the way they are produced.
		streamId := preds[pk.Attr]
		if streamId == 0 {
			streamId = atomic.AddUint32(&r.streamId, 1)
			preds[pk.Attr] = streamId
		}

		kv.StreamId = streamId
	}

	// Once we have processed all records from single stream, we can mark that stream as done.
	// This will close underlying table builder in Badger for stream. Since we preallocate 1 MB
	// of memory for each table builder, this can result in memory saving in case we have large
	// number of streams.
	// This change limits maximum number of open streams to number of streams created in a single
	// write call. This can also be optimised if required.
	// addDone := func(doneSteams []uint32, l *bpb.KVList) {
	// 	for _, streamId := range doneSteams {
	// 		l.Kv = append(l.Kv, &bpb.KV{StreamId: streamId, StreamDone: true})
	// 	}
	// }

	// var doneStreams []uint32
	// var prevSID uint32
	for batch := range entryCh {
		sort.Slice(batch, func(i, j int) bool {
			return less(batch[i], batch[j])
		})
		//listSize += r.toList(batch, list)
		if listSize > 4<<20 {
			for _, kv := range list.Kv {
				setStreamId(kv)
				// if prevSID != 0 && (prevSID != kv.StreamId) {
				// 	doneStreams = append(doneStreams, prevSID)
				// }
				// prevSID = kv.StreamId
			}
			// addDone(doneStreams, list)
			x.Check(writer.Write(list))
			//doneStreams = doneStreams[:0]
			list = &bpb.KVList{}
			listSize = 0
		}
	}
	if len(list.Kv) > 0 {
		for _, kv := range list.Kv {
			setStreamId(kv)
		}
		x.Check(writer.Write(list))
	}
}

func (r *reducer) reduce(partitionKeys []*pb.MapEntry, mapItrs []*mapIterator, ci *countIndexer) {
	cpu := runtime.NumCPU()
	fmt.Printf("Num CPUs: %d\n", cpu)
	encoderCh := make(chan *encodeRequest, 2*cpu)
	writerCh := make(chan *encodeRequest, 2*cpu)
	encoderCloser := y.NewCloser(cpu)
	for i := 0; i < runtime.NumCPU(); i++ {
		// Start listening to encode entries
		// For time being let's lease 100 stream id for each encoder.
		go r.encode(encoderCh, encoderCloser)
	}
	// Start lisenting to write the badger list.
	writerCloser := y.NewCloser(1)
	go r.startWriting(ci, writerCh, writerCloser)

	for i := 0; i < len(partitionKeys); i++ {
		batch := make([][]byte, 0, batchAlloc)
		numInvalid := 0
		for _, itr := range mapItrs {
			itr.Next()
			res := itr.Current()
			if res == nil {
				numInvalid++
				continue
			}
			y.AssertTrue(bytes.Compare(res.partitionKey.GetKey(), partitionKeys[i].GetKey()) == 0)
			batch = append(batch, res.batch...)
			itr.release(res)
		}
		if len(mapItrs) == numInvalid {
			if len(batch) == 0 {
				break
			}
		}
		wg := new(sync.WaitGroup)
		wg.Add(1)
		req := &encodeRequest{entries: batch, wg: wg}
		atomic.AddInt32(&r.prog.numEncoding, 1)
		encoderCh <- req
		writerCh <- req
	}

	// Drain the last batch
	batch := make([][]byte, 0, batchAlloc)
	for _, itr := range mapItrs {
		itr.Next()
		res := itr.Current()
		y.AssertTrue(res.partitionKey == nil)
		batch = append(batch, res.batch...)
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	req := &encodeRequest{entries: batch, wg: wg}
	atomic.AddInt32(&r.prog.numEncoding, 1)
	encoderCh <- req
	writerCh <- req

	// Close the encoders
	close(encoderCh)
	encoderCloser.SignalAndWait()

	// Close the writer
	close(writerCh)
	writerCloser.SignalAndWait()
}

func (r *reducer) toList(bufEntries [][]byte, list *bpb.KVList) []*countIndexEntry {

	sort.Slice(bufEntries, func(i, j int) bool {
		lh, err := GetKeyForMapEntry(bufEntries[i])
		x.Check(err)
		rh, err := GetKeyForMapEntry(bufEntries[j])
		x.Check(err)
		return bytes.Compare(lh, rh) < 0
	})
	// Don't parse to pb.MapEntries. Sort by keys only first.
	// Then pick all top entries [][]byte with the same key.
	// Parse them, convert to MapEntries only the ones with the same key, Sort again (no need to
	// sort by key. Only sort by uid).
	// Then, appendToList.
	// Reuse the freelist of map entries somehow. Maybe encode can pass the freelist?

	var currentKey []byte
	var uids []uint64
	var size int
	pl := new(pb.PostingList)

	userMeta := []byte{posting.BitCompletePosting}
	writeVersionTs := r.state.writeTs

	countEntries := []*countIndexEntry{}
	currentBatch := make([]*pb.MapEntry, 0, 100)
	freelist := make([]*pb.MapEntry, 0)

	appendToList := func() {
		if len(currentBatch) == 0 {
			return
		}
		// calculate count entries
		countEntries = append(countEntries, &countIndexEntry{
			key:   y.Copy(currentKey),
			count: len(currentBatch),
		})
		// Now make a list and write it to badger
		sort.Slice(currentBatch, func(i, j int) bool {
			return less(currentBatch[i], currentBatch[j])
		})
		for _, mapEntry := range currentBatch {
			uid := mapEntry.Uid
			if mapEntry.Posting != nil {
				uid = mapEntry.Posting.Uid
			}
			if len(uids) > 0 && uids[len(uids)-1] == uid {
				continue
			}
			// TODO: Potentially could be doing codec.Encoding right here.
			uids = append(uids, uid)
			if mapEntry.Posting != nil {
				pl.Postings = append(pl.Postings, mapEntry.Posting)
			}
		}

		atomic.AddInt64(&r.prog.reduceKeyCount, 1)

		// For a UID-only posting list, the badger value is a delta packed UID
		// list. The UserMeta indicates to treat the value as a delta packed
		// list when the value is read by dgraph.  For a value posting list,
		// the full pb.Posting type is used (which pb.y contains the
		// delta packed UID list).
		if len(uids) == 0 {
			return
		}

		// If the schema is of type uid and not a list but we have more than one uid in this
		// list, we cannot enforce the constraint without losing data. Inform the user and
		// force the schema to be a list so that all the data can be found when Dgraph is started.
		// The user should fix their data once Dgraph is up.
		parsedKey, err := x.Parse(currentKey)
		x.Check(err)
		if parsedKey.IsData() {
			schema := r.state.schema.getSchema(parsedKey.Attr)
			if schema.GetValueType() == pb.Posting_UID && !schema.GetList() && len(uids) > 1 {
				fmt.Printf("Schema for pred %s specifies that this is not a list but more than  "+
					"one UID has been found. Forcing the schema to be a list to avoid any "+
					"data loss. Please fix the data to your specifications once Dgraph is up.\n",
					parsedKey.Attr)
				r.state.schema.setSchemaAsList(parsedKey.Attr)
			}
		}

		pl.Pack = codec.Encode(uids, 256)
		val, err := pl.Marshal()
		x.Check(err)
		kv := &bpb.KV{
			Key:      y.Copy(currentKey),
			Value:    val,
			UserMeta: userMeta,
			Version:  writeVersionTs,
		}
		size += kv.Size()
		list.Kv = append(list.Kv, kv)
		uids = uids[:0]
		pl.Reset()
		// Now we have written the list. It's time to reuse the current batch.
		freelist = append(freelist, currentBatch...)
		// reset the current batch
		currentBatch = currentBatch[:0]
	}
	for _, entry := range bufEntries {
		atomic.AddInt64(&r.prog.reduceEdgeCount, 1)
		entryKey, err := GetKeyForMapEntry(entry)
		x.Check(err)
		if !bytes.Equal(entryKey, currentKey) && currentKey != nil {
			appendToList()
		}
		currentKey = append(currentKey[:0], entryKey...)
		var mapEntry *pb.MapEntry
		if len(freelist) == 0 {
			// Create a new map entry
			mapEntry = &pb.MapEntry{}
		} else {
			// Obtain from free list
			mapEntry = freelist[0]
			mapEntry.Reset()
			freelist = freelist[1:]
		}
		x.Check(mapEntry.Unmarshal(entry))
		entry = nil
		currentBatch = append(currentBatch, mapEntry)
	}
	appendToList()
	return countEntries
}
