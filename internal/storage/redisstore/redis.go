package redisstore

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"nexaflow/internal/model"
)

type Store struct {
	addr string
}

func New(addr string) *Store {
	return &Store{addr: addr}
}

func (s *Store) WriteWindow(ctx context.Context, win model.WindowResult) error {
	conn, err := net.DialTimeout("tcp", s.addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	linkKey := fmt.Sprintf("rt:link:%s:%d", win.SourceID, win.Ts)
	if err := send(conn, "HSET", linkKey, "bytes", strconv.FormatUint(win.Link.Bytes, 10), "packets", strconv.FormatUint(win.Link.Packets, 10), "utilization", fmt.Sprintf("%f", win.Link.Util)); err != nil {
		return err
	}
	if err := send(conn, "EXPIRE", linkKey, "7200"); err != nil {
		return err
	}
	writeTop(conn, "rt:top:ip:src:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopSrcIP)
	writeTop(conn, "rt:top:ip:dst:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopDstIP)
	writeTop(conn, "rt:top:port:dst:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopDstPort)
	writeTop(conn, "rt:top:proto:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopProtocol)
	writeTop(conn, "rt:top:flow:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopFlow)
	writeTop(conn, "rt:top:pair:"+win.SourceID+":"+strconv.FormatInt(win.Ts, 10), win.TopPair)
	return nil
}

func writeTop(conn net.Conn, key string, rows []model.TopItem) {
	for _, row := range rows {
		_ = send(conn, "ZADD", key, strconv.FormatUint(row.Bytes, 10), row.Key)
	}
	_ = send(conn, "EXPIRE", key, "7200")
}

func send(conn net.Conn, args ...string) error {
	var buf []byte
	buf = append(buf, '*')
	buf = append(buf, strconv.Itoa(len(args))...)
	buf = append(buf, "\r\n"...)
	for _, arg := range args {
		buf = append(buf, '$')
		buf = append(buf, strconv.Itoa(len(arg))...)
		buf = append(buf, "\r\n"...)
		buf = append(buf, arg...)
		buf = append(buf, "\r\n"...)
	}
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	var resp [256]byte
	_, err := conn.Read(resp[:])
	return err
}
