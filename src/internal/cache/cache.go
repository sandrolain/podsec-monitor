package cache

import (
	"github.com/nutsdb/nutsdb"
)

const procImagesBucket = "procImages"

func Init(dirPath string) (res *Cache, err error) {
	db, err := nutsdb.Open(
		nutsdb.DefaultOptions,
		nutsdb.WithDir(dirPath),
	)
	if err != nil {
		return
	}

	err = db.Update(func(tx *nutsdb.Tx) error {
		if tx.ExistBucket(nutsdb.DataStructureBTree, procImagesBucket) {
			return nil
		}
		return tx.NewBucket(nutsdb.DataStructureBTree, procImagesBucket)
	})
	if err != nil {
		return
	}

	res = &Cache{db: db}
	return
}

type Cache struct {
	db *nutsdb.DB
}

func (c *Cache) Set(key string, value string, ttl uint32) (err error) {
	err = c.db.Update(func(tx *nutsdb.Tx) error {
		return tx.Put(procImagesBucket, []byte(key), []byte(value), ttl)
	})
	return
}

func (c *Cache) Get(key string) (res string, err error) {
	err = c.db.View(func(tx *nutsdb.Tx) (err error) {
		resBytes, err := tx.Get(procImagesBucket, []byte(key))
		if err == nil {
			res = string(resBytes)
		}
		return
	})
	return
}

func (c *Cache) Close() {
	c.db.Close()
}
