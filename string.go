package keys

// import (
// 	"math/rand"
// 	"sync"
// 	"time"

// 	"github.com/google/uuid"
// )

// var m *sync.Mutex = &sync.Mutex{}
// var key int = 94216435916
// var subscribed map[string]func(newkey, oldkey int)

// func init() {
// 	go func() {
// 		for {
// 			rand.Seed(time.Since(time.Date(2020, time.September, 3, 4, 4, 0, 0, time.UTC)).Nanoseconds())
// 			newkey := rand.Intn(int(^uint(0) >> 1))
// 			for _, s := range subscribed {
// 				s(newkey, key)
// 			}
// 			key = newkey

// 			time.Sleep(time.Second * 30)
// 		}
// 	}()
// }

// type EncryptedString string
// type DecryptedString string

// func NewSecureKey(value string) *secureKey {
// 	m.Lock()
// 	defer m.Unlock()

// 	newVal := make([]rune, len(value))
// 	for i, v := range []rune(value) {
// 		newVal[i] = rune(int(v) ^ key)
// 	}

// 	sk := &secureKey{
// 		id:    uuid.NewString(),
// 		value: newVal,
// 	}

// 	subscribed[sk.id] = sk.setNewKey
// 	return sk
// }

// type secureKey struct {
// 	id    string
// 	value []rune
// }

// func (sk *secureKey) setNewKey(oldKey, newKey int) {
// 	for i, v := range sk.value {
// 		sk.value[i] = rune(newKey ^ (oldKey ^ int(v)))
// 	}
// }

// func (sk *secureKey) xor(vals []rune) []rune {
// 	newRune := make([]rune, len(vals))
// 	for i, v := range vals {
// 		newRune[i] = rune(key ^ int(v))
// 	}

// 	return newRune
// }

// func (sk *secureKey) Delete() {
// 	m.Lock()
// 	defer m.Unlock()

// 	sk.value = nil
// 	delete(subscribed, sk.id)
// }

// func (sk *secureKey) GetValue() []rune {
// 	return sk.xor(sk.value)
// }
