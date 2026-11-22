package proto

import "encoding/json"

// Message is the single E2EE JSON envelope exchanged between controller host and target guest.
type Message struct {
	ID      string          `json:"id,omitempty"`
	Kind    string          `json:"kind"` // "req", "resp", "event"
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
	OK      bool            `json:"ok,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// GuestHello is sent by guest immediately after E2EE handshake succeeds.
type GuestHello struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	OSPretty string `json:"os_pretty"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	Cwd      string `json:"cwd"`
	Mode     string `json:"mode"` // "confirm" (default), "ro", "full"
}

type ReadFileReq struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"` // 1-based inclusive
	EndLine   int    `json:"end_line,omitempty"`   // 1-based inclusive; 0 means to end (within limit)
}

type ReadFileResp struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	TotalLines int    `json:"total_lines"`
	Truncated  bool   `json:"truncated"`
}

type ListDirReq struct {
	Path  string `json:"path"`
	Depth int    `json:"depth,omitempty"` // 1..3
}

type DirEntry struct {
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
}

type ListDirResp struct {
	Path      string     `json:"path"`
	Entries   []DirEntry `json:"entries"`
	Truncated bool       `json:"truncated"`
}

type GrepReq struct {
	Pattern    string `json:"pattern"`
	Path       string `json:"path"`
	MaxMatches int    `json:"max_matches,omitempty"`
}

type GrepMatch struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type GrepResp struct {
	Matches   []GrepMatch `json:"matches"`
	Truncated bool        `json:"truncated"`
}

type SysInfoResp struct {
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	OSPretty string `json:"os_pretty"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	Cwd      string `json:"cwd"`
	Memory   string `json:"memory"`
	Disk     string `json:"disk"`
	GPU      string `json:"gpu,omitempty"`
}

type ExecReq struct {
	Command    string `json:"command"`
	Cwd        string `json:"cwd,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

type ExecResp struct {
	Command  string `json:"command"`
	Cwd      string `json:"cwd"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	ReadOnly bool   `json:"read_only"`
	Approved bool   `json:"approved"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

type EditFileReq struct {
	Path       string `json:"path"`
	OldText    string `json:"old_text"`
	NewText    string `json:"new_text"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

type WriteFileReq struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    uint32 `json:"mode,omitempty"`
}

type ModifyFileResp struct {
	Path          string `json:"path"`
	Diff          string `json:"diff"`
	BeforeContent string `json:"before_content"`
	Approved      bool   `json:"approved"`
	Created       bool   `json:"created,omitempty"`
	BytesWritten  int    `json:"bytes_written"`
	Replacements  int    `json:"replacements,omitempty"`
}

type ScreenshotResp struct {
	PNGBase64 string `json:"png_base64"`
	Tool      string `json:"tool"`
	Approved  bool   `json:"approved"`
}

type PullInitReq struct {
	Path string `json:"path"`
}

type PullInitResp struct {
	PullID   string `json:"pull_id,omitempty"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Approved bool   `json:"approved"`
}

type PullChunkReq struct {
	PullID string `json:"pull_id"`
	Offset int64  `json:"offset"`
	Size   int    `json:"size"`
}

type PullChunkResp struct {
	DataBase64 string `json:"data_base64,omitempty"`
	BytesRead  int    `json:"bytes_read"`
	EOF        bool   `json:"eof"`
	SHA256     string `json:"sha256,omitempty"`
}
