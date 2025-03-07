package memfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MemFS 代表内存文件系统，是整个内存文件系统的根。
type MemFS struct {
	root *MemDir      // 根目录
	mu   sync.RWMutex // 读写锁，用于保护并发访问
}

// Node 接口，定义了文件和目录都需要实现的通用方法。
type Node interface {
	Name() string       // 获取节点名称
	IsDir() bool        // 判断是否为目录
	Mode() os.FileMode  // 获取权限模式
	ModTime() time.Time // 获取修改时间
	Size() int64        // 获取大小
}

// MemDir 代表内存目录，实现了 Node 接口。
type MemDir struct {
	name     string          // 目录名称
	mode     os.FileMode     // 权限模式
	modTime  time.Time       // 修改时间
	parent   *MemDir         // 父目录
	Children map[string]Node // 子节点列表
}

// MemFile 代表内存文件，实现了 Node 接口。
type MemFile struct {
	name    string
	mode    os.FileMode
	modTime time.Time
	parent  *MemDir
	content []byte
}

// 确保 MemDir 和 MemFile 实现了 Node 接口
var _ Node = (*MemDir)(nil)
var _ Node = (*MemFile)(nil)

// --- 自定义错误类型 ---
// 定义了内存文件系统可能出现的各种错误类型。
var (
	ErrPathNotFound     = errors.New("path not found")               // 路径不存在
	ErrFileExists       = errors.New("file already exists")          // 文件已存在
	ErrDirExists        = errors.New("directory already exists")     // 目录已存在
	ErrNotEmptyDir      = errors.New("directory is not empty")       // 目录非空
	ErrInvalidPath      = errors.New("invalid path")                 // 无效路径
	ErrPermissionDenied = errors.New("permission denied")            // 权限不足
	ErrInvalidSize      = errors.New("invalid size")                 // 无效大小
	ErrNotDirectory     = errors.New("not a directory")              // 不是目录
	ErrNotFile          = errors.New("not a file")                   // 不是文件
	ErrRootRemoval      = errors.New("cannot remove root directory") // 尝试删除根目录
)

// PathError 包含路径信息的错误
type PathError struct {
	Op   string
	Path string
	Err  error
}

// Error 返回包含操作、路径和错误信息的字符串。
func (e *PathError) Error() string {
	return fmt.Sprintf("%s '%s': %v", e.Op, e.Path, e.Err) // 格式化错误信息，包含操作、路径和具体错误
}

// Unwrap 返回内部的错误，用于 errors.Is 和 errors.As。

func (e *PathError) Unwrap() error { return e.Err }

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrPathNotFound)
}

func isExist(err error) bool {
	return errors.Is(err, os.ErrExist) || errors.Is(err, ErrFileExists) || errors.Is(err, ErrDirExists)
}

func isNotDir(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrNotDirectory)
}

func isNotFile(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrNotFile)
}

// --- Node 接口实现 ---

// Name 返回目录节点的名称。
func (d *MemDir) Name() string { return d.name }

// IsDir 判断目录节点是否为目录，总是返回 true。
func (d *MemDir) IsDir() bool { return true }

// Mode 返回目录节点的权限模式。
func (d *MemDir) Mode() os.FileMode { return d.mode }

// ModTime 返回目录节点的修改时间。
func (d *MemDir) ModTime() time.Time { return d.modTime }

// Size 返回目录节点的大小，目录大小通常不代表数据大小，此处固定返回 0。
func (d *MemDir) Size() int64 { return 0 }

// Name 返回文件节点的名称。
func (f *MemFile) Name() string { return f.name }

// IsDir 判断文件节点是否为目录，总是返回 false。
func (f *MemFile) IsDir() bool { return false }

// Mode 返回文件节点的权限模式。
func (f *MemFile) Mode() os.FileMode { return f.mode }

// ModTime 返回文件节点的修改时间。
func (f *MemFile) ModTime() time.Time { return f.modTime }

// Size 返回文件节点内容的大小。
func (f *MemFile) Size() int64 { return int64(len(f.content)) }

// --- MemFS 的构造函数 ---

// NewMemFS 创建一个新的内存文件系统，并初始化根目录。
func NewMemFS() *MemFS {
	root := &MemDir{
		name:     "/",
		mode:     os.ModeDir | 0755, // 默认根目录权限为 0755
		modTime:  time.Now(),
		Children: make(map[string]Node),
	}
	return &MemFS{root: root, mu: sync.RWMutex{}}
}

// ResolvePath 根据路径字符串解析 Node，返回对应的节点和父目录，使用读锁保护。
func (fs *MemFS) ResolvePath(path string) (Node, *MemDir, error) {
	fs.mu.RLock() // 获取读锁
	defer fs.mu.RUnlock()

	if path == "" || path == "/" {
		return fs.root, nil, nil // 根目录
	}

	pathParts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	currentDir := fs.root       // 从根目录开始
	var parentDir *MemDir = nil // 记录父目录，初始为 nil

	for _, part := range pathParts[1:] { // 遍历路径的每个部分，跳过第一个空字符串（根目录）
		if part == "" { // 忽略空路径部分，例如连续的斜杠
			continue
		}
		node, ok := currentDir.Children[part]
		if !ok {
			return nil, parentDir, &PathError{"resolve path", path, ErrPathNotFound} // 路径不存在，返回错误
		}
		parentDir = currentDir // 更新父目录为当前目录
		if dir, isDir := node.(*MemDir); isDir {
			currentDir = dir // 如果是目录，则进入该目录
		} else if _, isFile := node.(*MemFile); isFile {
			if part == pathParts[len(pathParts)-1] { // 如果是路径的最后一部分且是文件，则返回该文件
				return node, parentDir, nil // 找到文件，返回文件节点和父目录
			} else {
				return nil, parentDir, &PathError{"resolve path", path, ErrPathNotFound} // 中间路径部分是文件，路径无效
			}
		} else { // 未知节点类型，理论上不应该出现
			return nil, parentDir, &PathError{"resolve path", path, ErrPathNotFound}
		}
	}

	return currentDir, parentDir, nil // 返回找到的目录
}

// --- MemFS 的文件操作方法 ---  以下方法都需要加锁

// CreateFile 创建一个新的内存文件，返回一个 io.WriteCloser 用于写入文件内容。
func (fs *MemFS) CreateFile(path string) (io.WriteCloser, error) {
	dirPath := filepath.Dir(path)
	fileName := filepath.Base(path)

	parentDirNode, _, err := fs.ResolvePath(dirPath)
	if err != nil {
		return nil, err
	}
	parentDir, ok := parentDirNode.(*MemDir)
	if !ok {
		return nil, &PathError{"create file", dirPath, ErrNotDirectory} // 父路径不是目录，返回错误
	}

	fs.mu.Lock() // 获取写锁，确保并发安全
	defer fs.mu.Unlock()

	if _, exists := parentDir.Children[fileName]; exists { // 检查文件是否已存在
		return nil, &PathError{"create file", path, ErrFileExists} // 文件已存在，返回自定义错误
	}

	file := &MemFile{
		name:    fileName,
		mode:    0644, // 默认文件权限
		modTime: time.Now(),
		parent:  parentDir,
		content: []byte{},
	}
	parentDir.Children[fileName] = file

	return &memFileWriter{file: file, mu: &fs.mu}, nil
}

// OpenFile 打开一个内存文件用于读取，返回一个 io.ReadCloser 用于读取文件内容。
func (fs *MemFS) OpenFile(path string) (io.ReadCloser, error) {
	node, _, err := fs.ResolvePath(path)
	if err != nil {
		return nil, err
	}
	file, ok := node.(*MemFile)
	if !ok {
		return nil, &PathError{"open file", path, ErrNotFile} // 路径不是文件，返回错误
	}
	return &memFileReader{file: file, mu: &fs.mu}, nil
}

// Truncate 截断文件，将文件内容截断为指定大小。
// Truncate 截断文件
func (fs *MemFS) Truncate(path string, size int64) error {
	node, _, err := fs.ResolvePath(path)
	if err != nil {
		return err
	}
	file, ok := node.(*MemFile)
	if !ok {
		return &PathError{"truncate file", path, ErrNotFile} // 路径不是文件，返回错误
	}

	fs.mu.Lock() // 获取写锁，确保并发安全
	defer fs.mu.Unlock()

	if size < 0 { // 检查大小是否有效
		return &PathError{"truncate file", path, ErrInvalidSize} // 无效尺寸，返回自定义错误
	}

	if size > int64(cap(file.content)) {
		newContent := make([]byte, size)
		copy(newContent, file.content)
		file.content = newContent
	}
	file.content = file.content[:size]
	file.modTime = time.Now()
	return nil
}

// --- MemFS 的目录操作方法 --- 以下方法都需要加锁

// Mkdir 创建目录，perm 指定目录的权限。
func (fs *MemFS) Mkdir(path string, perm os.FileMode) error {
	dirPath := filepath.Dir(path)
	dirName := filepath.Base(path)

	parentDirNode, _, err := fs.ResolvePath(dirPath)
	if err != nil {
		return err
	}
	parentDir, ok := parentDirNode.(*MemDir)
	if !ok {
		return &PathError{"mkdir", dirPath, ErrNotDirectory} // 父路径不是目录，返回错误
	}

	fs.mu.Lock() // 获取写锁，确保并发安全
	defer fs.mu.Unlock()

	if _, exists := parentDir.Children[dirName]; exists { // 检查目录是否已存在
		return &PathError{"mkdir", path, ErrDirExists} // 目录已存在，返回自定义错误
	}

	newDir := &MemDir{
		name:     dirName,
		mode:     os.ModeDir | perm,
		modTime:  time.Now(),
		parent:   parentDir,
		Children: make(map[string]Node),
	}
	parentDir.Children[dirName] = newDir
	return nil
}

// Readdir 读取目录下的文件信息，count 指定读取的文件数量，如果 count <= 0 则读取所有文件。
func (fs *MemFS) Readdir(path string, count int) ([]os.FileInfo, error) {
	dirNode, _, err := fs.ResolvePath(path)
	if err != nil {
		return nil, err
	}
	dir, ok := dirNode.(*MemDir)
	if !ok {
		return nil, &PathError{"readdir", path, ErrNotDirectory} // 路径不是目录，返回错误
	}

	fs.mu.RLock() // 获取读锁，允许多个读取操作并发进行
	defer fs.mu.RUnlock()

	var files []os.FileInfo
	i := 0
	for _, node := range dir.Children {
		files = append(files, memFileInfo{node: node})
		i++
		if count > 0 && i >= count { // count > 0 时限制数量
			break
		}
	}
	return files, nil
}

// Remove 删除文件或目录，如果目录非空则返回错误。
func (fs *MemFS) Remove(path string) error {
	node, parentDir, err := fs.ResolvePath(path)
	if err != nil {
		return err
	}
	if parentDir == nil {
		return &PathError{"remove", path, ErrRootRemoval} // 不允许删除根目录，返回自定义错误
	}

	fs.mu.Lock() // 获取写锁，确保并发安全
	defer fs.mu.Unlock()

	if dir, isDir := node.(*MemDir); isDir {
		if len(dir.Children) > 0 {
			return &PathError{"remove", path, ErrNotEmptyDir} // 目录非空，返回自定义错误
		} // 如果是目录，且目录非空，则返回错误
	}

	delete(parentDir.Children, node.Name())
	return nil
}

// --- MemFS 的信息查询方法 ---
// Stat 获取文件或目录的信息，返回 os.FileInfo 接口。
// Stat 获取文件或目录信息
func (fs *MemFS) Stat(path string) (os.FileInfo, error) {
	node, _, err := fs.ResolvePath(path)
	if err != nil {
		return nil, err
	}
	return memFileInfo{node: node}, nil
}

// --- MemFS 的刷写方法 --- 以下方法都需要加锁

// FlushToDisk 将 MemFS 的内容刷写到磁盘目录，diskPath 指定磁盘上的目录路径。
func (fs *MemFS) FlushToDisk(diskPath string) error {
	fs.mu.Lock() // 获取写锁
	defer fs.mu.Unlock()

	return fs.flushDirToDisk(fs.root, diskPath)
}

// flushDirToDisk 递归地将内存目录及其子节点刷写到磁盘。
func (fs *MemFS) flushDirToDisk(memDir *MemDir, diskPath string) error {
	err := os.MkdirAll(diskPath, memDir.Mode().Perm()) // 创建目录，如果已存在则不操作
	if err != nil && !os.IsExist(err) {
		return err
	}

	for name, node := range memDir.Children {
		diskNodePath := filepath.Join(diskPath, name)
		if memFile, isFile := node.(*MemFile); isFile {
			err = fs.flushFileToDisk(memFile, diskNodePath)
			if err != nil {
				return err
			}
		} else if memSubDir, isDir := node.(*MemDir); isDir {
			err = fs.flushDirToDisk(memSubDir, diskNodePath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// flushFileToDisk 将内存文件刷写到磁盘。
func (fs *MemFS) flushFileToDisk(memFile *MemFile, diskPath string) error {
	file, err := os.OpenFile(diskPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, memFile.Mode().Perm())
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(memFile.content)
	if err != nil {
		return err
	}
	return nil
}

// --- memFileReader 结构体和方法 ---  以下方法都需要加锁

// memFileReader 用于读取内存文件，实现了 io.Reader 和 io.Closer 接口。
type memFileReader struct {
	file   *MemFile      // 要读取的文件
	offset int64         // 当前读取的偏移量
	mu     *sync.RWMutex // 使用 MemFS 的读写锁，确保并发安全
}

// Read 实现 io.Reader 接口
func (r *memFileReader) Read(p []byte) (n int, err error) {
	r.mu.RLock() // 获取读锁
	defer r.mu.RUnlock()

	if r.offset >= int64(len(r.file.content)) {
		return 0, io.EOF
	}
	n = copy(p, r.file.content[r.offset:])
	r.offset += int64(n)
	return n, nil
}

// Close 实现 io.Closer 接口 (内存文件读取无需实际关闭操作)
func (*memFileReader) Close() error {
	return nil // 内存文件读取无需关闭
}

// --- memFileWriter 结构体和方法 --- 以下方法都需要加锁

// memFileWriter 用于写入内存文件，实现了 io.Writer 和 io.Closer 接口。
type memFileWriter struct {
	file      *MemFile      // 要写入的文件
	mu        *sync.RWMutex // 使用 MemFS 的读写锁，确保并发安全
	offset    int64         // 当前写入的偏移量
	buffer    []byte        // 写入缓冲区
	bufOffset int64         // 缓冲区偏移量 (暂未使用，可以用于更复杂的缓冲策略)
}

// Write 实现 io.Writer 接口
func (w *memFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock() // 获取写锁
	defer w.mu.Unlock()

	if w.buffer == nil {
		w.buffer = make([]byte, 0, 4096) // 初始化缓冲区，可以调整大小
	}

	// 写入缓冲区
	w.buffer = append(w.buffer, p...)
	n = len(p)

	// 当缓冲区达到一定大小或写入内容较大时，将缓冲区内容刷新到文件
	if len(w.buffer) > 4096 || n > 1024 { // 可以根据实际情况调整刷新策略
		if err := w.flushBuffer(); err != nil {
			return 0, err
		}
	}

	return n, nil
}

// Close 实现 io.Closer 接口
func (w *memFileWriter) Close() error {
	w.mu.Lock() // 获取写锁
	defer w.mu.Unlock()
	return w.flushBuffer() // 关闭前刷新缓冲区
}

// flushBuffer 将缓冲区内容刷新到内存文件。
func (w *memFileWriter) flushBuffer() error {
	if len(w.buffer) == 0 {
		return nil // 缓冲区为空，无需刷新
	}

	currentLen := int64(len(w.file.content))
	offset64 := w.offset
	if offset64 > currentLen {
		offset64 = currentLen // 超过当前长度，追加到末尾
	}

	// 确保文件内容有足够的容量来写入 (扩容策略可以调整)
	if int(offset64)+len(w.buffer) > cap(w.file.content) {
		newContent := make([]byte, 0, int(offset64)+len(w.buffer)*2) // 扩容两倍
		newContent = append(newContent, w.file.content...)
		w.file.content = newContent
	}
	// 确保切片长度足够写入
	if int(offset64)+len(w.buffer) > len(w.file.content) {
		w.file.content = w.file.content[:int(offset64)+len(w.buffer)]
	}

	written := copy(w.file.content[offset64:], w.buffer)
	w.offset += int64(written)
	if w.offset > int64(len(w.file.content)) {
		w.file.content = w.file.content[:w.offset] // 更新文件内容长度
	}
	w.file.modTime = time.Now() // 更新修改时间
	w.buffer = w.buffer[:0]     // 清空缓冲区，但保留底层数组，避免频繁分配内存
	return nil
}

// --- memFileInfo 结构体和方法 --- 以下方法都需要加锁

// memFileInfo 实现了 os.FileInfo 接口，用于提供文件或目录的元信息。
type memFileInfo struct {
	node Node // 内部持有的节点
}

// Name 返回文件或目录名
func (fi memFileInfo) Name() string { return fi.node.Name() }

// Size 返回文件大小，目录返回 0
func (fi memFileInfo) Size() int64 { return fi.node.Size() }

// Mode 返回文件或目录的权限模式
func (fi memFileInfo) Mode() os.FileMode { return fi.node.Mode() }

// ModTime 返回文件或目录的修改时间
func (fi memFileInfo) ModTime() time.Time { return fi.node.ModTime() }

// IsDir 判断是否是目录
func (fi memFileInfo) IsDir() bool { return fi.node.IsDir() }

// Sys 返回底层数据源（这里返回 nil，因为是内存文件系统）
func (fi memFileInfo) Sys() interface{} { return nil }

// ModeDir 返回目录位 (辅助函数，可能在外部使用)。
func ModeDir() os.FileMode {
	return os.ModeDir
}
