package p2p

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/rs/zerolog/log"
)

var (
	timeout = 20 * time.Second
)

// Dial attempts to Dial the given node and perform a handshake,
// returning the created Conn if successful.
func Dial(n *enode.Node) (*rlpxConn, error) {
	fd, err := net.Dial("tcp", fmt.Sprintf("%v:%d", n.IP(), n.TCP()))
	if err != nil {
		return nil, err
	}

	conn := rlpxConn{
		Conn:   rlpx.NewConn(fd, n.Pubkey()),
		node:   n,
		logger: log.With().Str("peer", n.URLv4()).Logger(),
		caps: []p2p.Cap{
			{Name: "eth", Version: 66},
			{Name: "eth", Version: 67},
			{Name: "eth", Version: 68},
		},
	}

	if conn.ourKey, err = crypto.GenerateKey(); err != nil {
		return nil, err
	}

	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if err = conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, err
	}
	if _, err = conn.Handshake(conn.ourKey); err != nil {
		conn.Close()
		return nil, err
	}

	return &conn, nil
}

// Peer performs both the protocol handshake and the status message
// exchange with the node in order to Peer with it.
func (c *rlpxConn) Peer() (*Hello, *Status, error) {
	hello, err := c.handshake()
	if err != nil {
		return nil, nil, fmt.Errorf("handshake failed: %v", err)
	}
	status, err := c.statusExchange()
	if err != nil {
		return hello, nil, fmt.Errorf("status exchange failed: %v", err)
	}
	return hello, status, nil
}

// handshake performs a protocol handshake with the node.
func (c *rlpxConn) handshake() (*Hello, error) {
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	// write hello to client
	pub0 := crypto.FromECDSAPub(&c.ourKey.PublicKey)[1:]
	ourHandshake := &Hello{
		Version: 5,
		Caps:    c.caps,
		ID:      pub0,
	}
	if err := c.Write(ourHandshake); err != nil {
		return nil, fmt.Errorf("write to connection failed: %v", err)
	}

	// read hello from client
	switch msg := c.Read().(type) {
	case *Hello:
		if msg.Version >= 5 {
			c.SetSnappy(true)
		}
		return msg, nil
	case *Disconnect:
		return nil, fmt.Errorf("disconnect received: %v", msg)
	case *Disconnects:
		return nil, fmt.Errorf("disconnect received: %v", msg)
	default:
		return nil, fmt.Errorf("bad handshake: %v", msg)
	}
}

// statusExchange gets the Status message from the given node.
func (c *rlpxConn) statusExchange() (*Status, error) {
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, err
	}

	var status *Status
loop:
	for {
		switch msg := c.Read().(type) {
		case *Status:
			status = msg
			break loop
		case *Disconnect:
			return nil, fmt.Errorf("disconnect received: %v", msg)
		case *Disconnects:
			return nil, fmt.Errorf("disconnect received: %v", msg)
		case *Ping:
			if err := c.Write(&Pong{}); err != nil {
				c.logger.Error().Err(err).Msg("Write pong failed")
			}
		default:
			return nil, fmt.Errorf("bad status message: %v", msg)
		}
	}

	if err := c.Write(status); err != nil {
		return nil, fmt.Errorf("write to connection failed: %v", err)
	}

	return status, nil
}

// request stores the request ID and the block's hash.
type request struct {
	requestID uint64
	hash      common.Hash
}

// ReadAndServe reads messages from peers and writes it to a database.
func (c *rlpxConn) ReadAndServe(count *MessageCount) error {
	for {
		start := time.Now()

		for time.Since(start) < timeout {
			if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				c.logger.Error().Err(err).Msg("Failed to set read deadline")
			}

			switch msg := c.Read().(type) {
			case *Ping:
				atomic.AddInt32(&count.Pings, 1)
				c.logger.Trace().Msg("Received Ping")

				if err := c.Write(&Pong{}); err != nil {
					c.logger.Error().Err(err).Msg("Failed to write Pong response")
				}
			case *NewBlock:
				atomic.AddInt32(&count.Blocks, 1)
				c.logger.Trace().Str("hash", msg.Block.Hash().Hex()).Msg("Received NewBlock")
				if hash := types.DeriveSha(msg.Block.Transactions(), trie.NewStackTrie(nil)); hash != msg.Block.TxHash() {
					c.logger.Warn().
						Uint64("number", msg.Block.NumberU64()).
						Str("hash", msg.Block.Hash().Hex()).
						Int("len(txs)", len(msg.Block.Transactions())).
						Str("block.txhash", msg.Block.TxHash().String()).
						Str("generated txhash", hash.String()).
						Msg("Propagated block has invalid txs")
				}
			case *Error:
				atomic.AddInt32(&count.Errors, 1)
				c.logger.Trace().Err(msg.Unwrap()).Msg("Received Error")

				if !strings.Contains(msg.Error(), "timeout") {
					return msg.Unwrap()
				}
			case *Disconnect:
				atomic.AddInt32(&count.Disconnects, 1)
				c.logger.Debug().Msgf("Disconnect received: %v", msg)
			case *Disconnects:
				atomic.AddInt32(&count.Disconnects, 1)
				c.logger.Debug().Msgf("Disconnect received: %v", msg)
			default:
				c.logger.Debug().Interface("msg", msg).Int("code", msg.Code()).Msg("Received message")
			}
		}
	}
}

// processNewPooledTransactionHashes processes NewPooledTransactionHashes
// messages by requesting the transaction bodies.
func (c *rlpxConn) processNewPooledTransactionHashes(count *MessageCount, hashes []common.Hash) error {
	atomic.AddInt32(&count.TransactionHashes, int32(len(hashes)))
	c.logger.Trace().Msgf("Received %v NewPooledTransactionHashes", len(hashes))

	req := &GetPooledTransactions{
		RequestId:                   rand.Uint64(),
		GetPooledTransactionsPacket: hashes,
	}
	if err := c.Write(req); err != nil {
		c.logger.Error().Err(err).Msg("Failed to write GetPooledTransactions request")
		return err
	}

	return nil
}
