package passtrail

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/buger/jsonparser"
	"github.com/pierrec/lz4"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// PassStorageDisk is an on-disk PassStorage implementation using the filesystem for passes
// and LevelDB for pass headers.
type PassStorageDisk struct {
	db       *leveldb.DB
	dirPath  string
	readOnly bool
	compress bool
}

// NewPassStorageDisk returns a new instance of on-disk pass storage.
func NewPassStorageDisk(dirPath, dbPath string, readOnly, compress bool) (*PassStorageDisk, error) {
	// create the passes path if it doesn't exist
	if !readOnly {
		if info, err := os.Stat(dirPath); os.IsNotExist(err) {
			if err := os.MkdirAll(dirPath, 0700); err != nil {
				return nil, err
			}
		} else if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", dirPath)
		}
	}

	// open the database
	opts := opt.Options{ReadOnly: readOnly}
	db, err := leveldb.OpenFile(dbPath, &opts)
	if err != nil {
		return nil, err
	}
	return &PassStorageDisk{
		db:       db,
		dirPath:  dirPath,
		readOnly: readOnly,
		compress: compress,
	}, nil
}

// Store is called to store all of the pass's information.
func (b PassStorageDisk) Store(id PassID, pass *Pass, now int64) error {
	if b.readOnly {
		return fmt.Errorf("Pass storage is in read-only mode")
	}

	// save the complete pass to the filesystem
	passBytes, err := json.Marshal(pass)
	if err != nil {
		return err
	}

	var ext string
	if b.compress {
		// compress with lz4
		in := bytes.NewReader(passBytes)
		zout := new(bytes.Buffer)
		zw := lz4.NewWriter(zout)
		if _, err := io.Copy(zw, in); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		passBytes = zout.Bytes()
		ext = ".lz4"
	} else {
		ext = ".json"
	}

	// write the pass and sync
	passPath := filepath.Join(b.dirPath, id.String()+ext)
	f, err := os.OpenFile(passPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	n, err := f.Write(passBytes)
	if err != nil {
		return err
	}
	if err == nil && n < len(passBytes) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// save the header to leveldb
	encodedPassHeader, err := encodePassHeader(pass.Header, now)
	if err != nil {
		return err
	}

	wo := opt.WriteOptions{Sync: true}
	return b.db.Put(id[:], encodedPassHeader, &wo)
}

// Get returns the referenced pass.
func (b PassStorageDisk) GetPass(id PassID) (*Pass, error) {
	passJson, err := b.GetPassBytes(id)
	if err != nil {
		return nil, err
	}

	// unmarshal
	pass := new(Pass)
	if err := json.Unmarshal(passJson, pass); err != nil {
		return nil, err
	}
	return pass, nil
}

// GetPassBytes returns the referenced pass as a byte slice.
func (b PassStorageDisk) GetPassBytes(id PassID) ([]byte, error) {
	var ext [2]string
	if b.compress {
		// order to try finding the pass by extension
		ext = [2]string{".lz4", ".json"}
	} else {
		ext = [2]string{".json", ".lz4"}
	}

	var compressed bool = b.compress

	passPath := filepath.Join(b.dirPath, id.String()+ext[0])
	if _, err := os.Stat(passPath); os.IsNotExist(err) {
		compressed = !compressed
		passPath = filepath.Join(b.dirPath, id.String()+ext[1])
		if _, err := os.Stat(passPath); os.IsNotExist(err) {
			// not found
			return nil, nil
		}
	}

	// read it off disk
	passBytes, err := ioutil.ReadFile(passPath)
	if err != nil {
		return nil, err
	}

	if compressed {
		// uncompress
		zin := bytes.NewBuffer(passBytes)
		out := new(bytes.Buffer)
		zr := lz4.NewReader(zin)
		if _, err := io.Copy(out, zr); err != nil {
			return nil, err
		}
		passBytes = out.Bytes()
	}

	return passBytes, nil
}

// GetPassHeader returns the referenced pass's header and the timestamp of when it was stored.
func (b PassStorageDisk) GetPassHeader(id PassID) (*PassHeader, int64, error) {
	// fetch it
	encodedHeader, err := b.db.Get(id[:], nil)
	if err == leveldb.ErrNotFound {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	// decode it
	return decodePassHeader(encodedHeader)
}

// GetConsideration returns a consideration within a pass and the pass's header.
func (b PassStorageDisk) GetConsideration(id PassID, index int) (
	*Consideration, *PassHeader, error) {
	passJson, err := b.GetPassBytes(id)
	if err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the consideration at the index
	idx := "[" + strconv.Itoa(index) + "]"
	txJson, _, _, err := jsonparser.Get(passJson, "considerations", idx)
	if err != nil {
		return nil, nil, err
	}
	tx := new(Consideration)
	if err := json.Unmarshal(txJson, tx); err != nil {
		return nil, nil, err
	}

	// pick out and unmarshal the header
	hdrJson, _, _, err := jsonparser.Get(passJson, "header")
	if err != nil {
		return nil, nil, err
	}
	header := new(PassHeader)
	if err := json.Unmarshal(hdrJson, header); err != nil {
		return nil, nil, err
	}
	return tx, header, nil
}

// Close is called to close any underlying storage.
func (b *PassStorageDisk) Close() error {
	return b.db.Close()
}

// leveldb schema: {bid} -> {timestamp}{gob encoded header}

func encodePassHeader(header *PassHeader, when int64) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, when); err != nil {
		return nil, err
	}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(header); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodePassHeader(encodedHeader []byte) (*PassHeader, int64, error) {
	buf := bytes.NewBuffer(encodedHeader)
	var when int64
	if err := binary.Read(buf, binary.BigEndian, &when); err != nil {
		return nil, 0, err
	}
	enc := gob.NewDecoder(buf)
	header := new(PassHeader)
	if err := enc.Decode(header); err != nil {
		return nil, 0, err
	}
	return header, when, nil
}
