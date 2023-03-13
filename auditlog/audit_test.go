package auditlog

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuditLog(t *testing.T) {
	db, err := New("")
	assert.NoError(t, err)
	defer db.Close()
	for i := 0; i < 100; i++ {
		err = db.Insert(
			net.ParseIP("127.0.0.1"), 48888,
			net.ParseIP("1.2.3.4"), 80,
			uint64(i), uint64(i)*2,
			ProtocolTCP, "a",
			time.Now(),
		)
		assert.NoError(t, err)
	}

	db.Flush()

	l, err := db.Query([]net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(l))
	assert.Equal(t, AccessLog{"a", 4950, 4950 * 2}, l[0])

	s, r, err := db.Total([]net.IP{net.ParseIP("127.0.0.1")})
	assert.NoError(t, err)
	assert.Equal(t, uint64(4950), s)
	assert.Equal(t, uint64(4950*2), r)
}

func BenchmarkAuditLog(b *testing.B) {
	db, err := New("")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Insert(
			net.ParseIP("127.0.0.1"), 48888,
			net.ParseIP("1.2.3.4"), 80,
			uint64(i), uint64(i)*2,
			ProtocolTCP, "a",
			time.Now(),
		)
	}
	db.Flush()
}

func BenchmarkQuery(b *testing.B) {
	db, err := New("")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	for i := 0; i < 1024; i++ {
		db.Insert(
			net.ParseIP("127.0.0.1"), 48888,
			net.ParseIP("1.2.3.4"), 80,
			uint64(i), uint64(i)*2,
			ProtocolTCP, "a",
			time.Now(),
		)
	}
	db.Flush()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Query([]net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), 1000)
	}
}
