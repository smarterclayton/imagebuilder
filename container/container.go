package container

import (
	"archive/tar"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/docker/docker/builder/dockerfile/parser"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/fileutils"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	"github.com/opencontainers/runc/libcontainer/user"

	"github.com/openshift/imagebuilder"
)

// Executor emulates docker builds by operating on the current filesystem.
type Executor struct {
	// Directory is the context directory to build from, will use
	// the current working directory if not set.
	Directory string
	// Excludes are a list of file patterns that should be excluded
	// from the context. Will be set to the contents of the
	// .dockerignore file if nil.
	Excludes []string
	// IgnoreUnrecognizedInstructions, if true, allows instructions
	// that are not yet supported to be ignored (will be printed)
	IgnoreUnrecognizedInstructions bool
	// TransientMounts are a set of mounts from outside the build
	// to the inside that will not be part of the final image. Any
	// content created inside the mount's destinationPath will be
	// omitted from the final image.
	TransientMounts []imagebuilder.Mount

	// The streams used for canonical output.
	Out, ErrOut io.Writer

	// LogFn is an optional command to log information to the end user
	LogFn func(format string, args ...interface{})

	// Deferred is a list of operations that must be cleaned up at
	// the end of execution. Use Release() to handle these.
	Deferred []func() error

	// Volumes handles saving and restoring volumes after RUN
	// commands are executed.
	Volumes *ContainerVolumeTracker
}

// NewExecutor creates a container executor, which builds inside of the current container.
func NewExecutor() *Executor {
	return &Executor{
		LogFn: func(string, ...interface{}) {},
	}
}

func (e *Executor) DefaultExcludes() error {
	excludes, err := imagebuilder.ParseDockerignore(e.Directory)
	if err != nil {
		return err
	}
	e.Excludes = append(excludes, ".dockerignore")
	return nil
}

// Build is a helper method to perform a Docker build against the
// provided Docker client. It will load the image if not specified,
// create a container if one does not already exist, and start a
// container if the Dockerfile contains RUN commands. It will cleanup
// any containers it creates directly, and set the e.Image.ID field
// to the generated image.
func (e *Executor) Build(b *imagebuilder.Builder, node *parser.Node, from string) error {
	defer e.Release()
	if err := e.Prepare(b, node, from); err != nil {
		return err
	}
	if err := e.Execute(b, node); err != nil {
		return err
	}
	return e.Commit(b)
}

func (e *Executor) Prepare(b *imagebuilder.Builder, node *parser.Node, from string) error {
	b.RunConfig.Image = from
	b.Excludes = e.Excludes

	// copy any source content into the temporary mount paths
	if len(e.TransientMounts) > 0 {
		restore, err := e.PopulateTransientMounts(e.TransientMounts)
		if err != nil {
			return err
		}
		e.Deferred = append(e.Deferred, restore)
	}
	return nil
}

// Execute performs all of the provided steps against the initialized container. May be
// invoked multiple times for a given container.
func (e *Executor) Execute(b *imagebuilder.Builder, node *parser.Node) error {
	for i, child := range node.Children {
		step := b.Step()
		if err := step.Resolve(child); err != nil {
			return err
		}
		glog.V(4).Infof("step: %s", step.Original)
		if e.LogFn != nil {
			// original may have unescaped %, so perform fmt escaping
			e.LogFn(strings.Replace(step.Original, "%", "%%", -1))
		}
		noRunsRemaining := !b.RequiresStart(&parser.Node{Children: node.Children[i+1:]})

		if err := b.Run(step, e, noRunsRemaining); err != nil {
			return err
		}
	}

	return nil
}

// Commit is a no-op.
func (e *Executor) Commit(b *imagebuilder.Builder) error {
	return nil
}

func (e *Executor) PopulateTransientMounts(transientMounts []imagebuilder.Mount) (func() error, error) {
	// var copies []imagebuilder.Copy
	// for i, mount := range transientMounts {
	// 	source := mount.SourcePath
	// 	copies = append(copies, imagebuilder.Copy{
	// 		Src:  []string{source},
	// 		Dest: filepath.Join(e.ContainerTransientMount, strconv.Itoa(i)),
	// 	})
	// }
	// if err := e.CopyContainer(container, nil, copies...); err != nil {
	// 	return nil, fmt.Errorf("unable to copy transient context into container: %v", err)
	// }

	// // mount individual items temporarily
	// var binds []string
	// for i, mount := range e.TransientMounts {
	// 	binds = append(binds, fmt.Sprintf("%s:%s:%s", filepath.Join(sharedMount, strconv.Itoa(i)), mount.DestinationPath, "ro"))
	// }
	// return binds, nil
	return nil, fmt.Errorf("transient mounts not yet implemented")
}

// Release deletes any items started by this executor.
func (e *Executor) Release() []error {
	var errs []error
	for _, fn := range e.Deferred {
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}
	e.Deferred = nil
	return errs
}

// randSeq returns a sequence of random characters drawn from source. It returns
// an error if cryptographic randomness is not available or source is more than 255
// characters.
func randSeq(source string, n int) (string, error) {
	if len(source) > 255 {
		return "", fmt.Errorf("source must be less than 256 bytes long")
	}
	random := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", err
	}
	for i := range random {
		random[i] = source[random[i]%byte(len(source))]
	}
	return string(random), nil
}

func (e *Executor) Preserve(path string) error {
	if e.Volumes == nil {
		e.Volumes = NewContainerVolumeTracker()
	}
	e.Volumes.Add(path)
	return nil
}

func (e *Executor) UnrecognizedInstruction(step *imagebuilder.Step) error {
	if e.IgnoreUnrecognizedInstructions {
		e.LogFn("warning: Unknown instruction: %s", strings.ToUpper(step.Command))
		return nil
	}
	return fmt.Errorf("Unknown instruction: %s", strings.ToUpper(step.Command))
}

// Run executes a single Run command against the current container using exec().
// Since exec does not allow ENV or WORKINGDIR to be set, we force the execution of
// the user command into a shell and perform those operations before. Since RUN
// requires /bin/sh, we can use both 'cd' and 'export'.
func (e *Executor) Run(run imagebuilder.Run, config docker.Config) error {
	args := make([]string, len(run.Args))
	copy(args, run.Args)

	if run.Shell {
		if runtime.GOOS == "windows" {
			// TODO: implement windows ENV
			args = append([]string{"cmd", "/S", "/C"}, args...)
		} else {
			args = append([]string{"/bin/sh", "-c"}, args...)
		}
	}

	if err := e.Volumes.Save(); err != nil {
		return err
	}

	config.Cmd = args
	glog.V(4).Infof("Running %v as user %s", config.Cmd, config.User)

	cmd := exec.Command(config.Cmd[0], config.Cmd[1:]...)
	cmd.Env = config.Env
	cmd.Dir = config.WorkingDir
	cmd.Stdout = e.Out
	cmd.Stderr = e.ErrOut
	// set user information or error
	if len(config.User) > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{},
		}
		var err error
		if parts := strings.SplitN(config.User, ":", 2); len(parts) > 1 {
			cmd.SysProcAttr.Credential.Uid, err = userForValue(parts[0])
			if err != nil {
				return err
			}
			cmd.SysProcAttr.Credential.Gid, err = groupForValue(parts[1])
			if err != nil {
				return err
			}
		} else {
			cmd.SysProcAttr.Credential.Uid, err = userForValue(config.User)
			if err != nil {
				return err
			}
		}
	}

	if err := cmd.Run(); err != nil {
		return err
	}

	if err := e.Volumes.Restore(); err != nil {
		return err
	}

	return nil
}

func userForValue(value string) (uint32, error) {
	if id, err := strconv.Atoi(value); err == nil {
		if id < 0 {
			return 0, fmt.Errorf("negative USER value not supported")
		}
		return uint32(id), nil
	}

	u, err := user.LookupUser(value)
	if err != nil {
		return 0, fmt.Errorf("unable to lookup USER %q: %v", value, err)
	}
	return uint32(u.Uid), nil
}

func groupForValue(value string) (uint32, error) {
	if id, err := strconv.Atoi(value); err == nil {
		if id < 0 {
			return 0, fmt.Errorf("negative group value not supported")
		}
		return uint32(id), nil
	}

	g, err := user.LookupGroup(value)
	if err != nil {
		return 0, fmt.Errorf("unable to lookup group %q: %v", value, err)
	}
	return uint32(g.Gid), nil
}

// Copy implements the executor copy function.
func (e *Executor) Copy(excludes []string, copies ...imagebuilder.Copy) error {
	// copying content into a volume invalidates the archived state of any given directory
	for _, copy := range copies {
		e.Volumes.Invalidate(copy.Dest)
	}

	return e.CopyContainer(excludes, copies...)
}

// CopyContainer copies the provided content into a destination container.
func (e *Executor) CopyContainer(excludes []string, copies ...imagebuilder.Copy) error {
	for _, c := range copies {
		// TODO: reuse source
		for _, src := range c.Src {
			glog.V(4).Infof("Archiving %s %t", src, c.Download)
			r, closer, err := e.Archive(src, c.Dest, c.Download, c.Download, excludes)
			if err != nil {
				return err
			}

			glog.V(5).Infof("Uploading to %s at %s", c.Dest)
			err = archive.Untar(r, "/", nil)
			if err := closer.Close(); err != nil {
				glog.Errorf("Error while closing stream container copy stream %s: %v", err)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type closers []func() error

func (c closers) Close() error {
	var lastErr error
	for _, fn := range c {
		if err := fn(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (e *Executor) Archive(src, dst string, allowDecompression, allowDownload bool, excludes []string) (io.Reader, io.Closer, error) {
	var closer closers
	var base string
	var infos []imagebuilder.CopyInfo
	var err error
	if imagebuilder.IsURL(src) {
		if !allowDownload {
			return nil, nil, fmt.Errorf("source can't be a URL")
		}
		infos, base, err = imagebuilder.DownloadURL(src, dst)
		if len(base) > 0 {
			closer = append(closer, func() error { return os.RemoveAll(base) })
		}
	} else {
		if filepath.IsAbs(src) {
			base = filepath.Dir(src)
			src, err = filepath.Rel(base, src)
			if err != nil {
				return nil, nil, err
			}
		} else {
			base = e.Directory
		}
		infos, err = imagebuilder.CalcCopyInfo(src, base, allowDecompression, true)
	}
	if err != nil {
		closer.Close()
		return nil, nil, err
	}

	options := archiveOptionsFor(infos, dst, excludes)

	glog.V(4).Infof("Tar of directory %s %#v", base, options)
	rc, err := archive.TarWithOptions(base, options)
	closer = append(closer, rc.Close)
	return rc, closer, err
}

func archiveOptionsFor(infos []imagebuilder.CopyInfo, dst string, excludes []string) *archive.TarOptions {
	dst = imagebuilder.TrimLeadingPath(dst)
	patterns, patDirs, _, _ := fileutils.CleanPatterns(excludes)
	options := &archive.TarOptions{}
	for _, info := range infos {
		if ok, _ := fileutils.OptimizedMatches(info.Path, patterns, patDirs); ok {
			continue
		}
		options.IncludeFiles = append(options.IncludeFiles, info.Path)
		if len(dst) == 0 {
			continue
		}
		if options.RebaseNames == nil {
			options.RebaseNames = make(map[string]string)
		}
		if info.FromDir || strings.HasSuffix(dst, "/") || strings.HasSuffix(dst, "/.") || dst == "." {
			if strings.HasSuffix(info.Path, "/") {
				options.RebaseNames[info.Path] = dst
			} else {
				options.RebaseNames[info.Path] = path.Join(dst, path.Base(info.Path))
			}
		} else {
			options.RebaseNames[info.Path] = dst
		}
	}
	options.ExcludePatterns = excludes
	return options
}

// ContainerVolumeTracker manages tracking archives of specific paths inside a container.
type ContainerVolumeTracker struct {
	paths map[string]string
	errs  []error
}

func NewContainerVolumeTracker() *ContainerVolumeTracker {
	return &ContainerVolumeTracker{
		paths: make(map[string]string),
	}
}

// Empty returns true if the tracker is not watching any paths
func (t *ContainerVolumeTracker) Empty() bool {
	return t == nil || len(t.paths) == 0
}

// Add tracks path unless it already is being tracked.
func (t *ContainerVolumeTracker) Add(path string) {
	if _, ok := t.paths[path]; !ok {
		t.paths[path] = ""
	}
}

// Release removes any stored snapshots
func (t *ContainerVolumeTracker) Release() []error {
	if t == nil {
		return nil
	}
	for path := range t.paths {
		t.ReleasePath(path)
	}
	return t.errs
}

func (t *ContainerVolumeTracker) ReleasePath(path string) {
	if t == nil {
		return
	}
	if archivePath, ok := t.paths[path]; ok && len(archivePath) > 0 {
		err := os.Remove(archivePath)
		if err != nil && !os.IsNotExist(err) {
			t.errs = append(t.errs, err)
		}
		glog.V(5).Infof("Releasing path %s (%v)", path, err)
		t.paths[path] = ""
	}
}

func (t *ContainerVolumeTracker) Invalidate(path string) {
	if t == nil {
		return
	}
	set := imagebuilder.VolumeSet{}
	set.Add(path)
	for path := range t.paths {
		if set.Covers(path) {
			t.ReleasePath(path)
		}
	}
}

// Save ensures that all paths tracked underneath this container are archived or
// returns an error.
func (t *ContainerVolumeTracker) Save() error {
	if t == nil {
		return nil
	}
	set := imagebuilder.VolumeSet{}
	for dest := range t.paths {
		set.Add(dest)
	}
	// remove archive paths that are covered by other paths
	for dest := range t.paths {
		if !set.Has(dest) {
			t.ReleasePath(dest)
			delete(t.paths, dest)
		}
	}
	for dest, archivePath := range t.paths {
		if len(archivePath) > 0 {
			continue
		}
		archivePath, err := snapshotPath(dest)
		if err != nil {
			return err
		}
		t.paths[dest] = archivePath
	}
	return nil
}

// filterTarPipe transforms a tar file as it is streamed, calling fn on each header in the file.
// If fn returns false, the file is skipped. If an error occurs it is returned.
func filterTarPipe(w *tar.Writer, r *tar.Reader, fn func(*tar.Header) bool) error {
	for {
		h, err := r.Next()
		if err != nil {
			return err
		}
		if fn(h) {
			if err := w.WriteHeader(h); err != nil {
				return err
			}
			if _, err := io.Copy(w, r); err != nil {
				return err
			}
		} else {
			if _, err := io.Copy(ioutil.Discard, r); err != nil {
				return err
			}
		}
	}
}

// snapshotPath preserves the contents of path in container containerID as a temporary
// archive, returning either an error or the path of the archived file.
func snapshotPath(path string) (string, error) {
	f, err := ioutil.TempFile("", "archived-path")
	if err != nil {
		return "", err
	}
	glog.V(4).Infof("Snapshot %s for later use under %s", path, f.Name())

	r, w := io.Pipe()
	tr := tar.NewReader(r)
	tw := tar.NewWriter(f)
	go func() {
		err := filterTarPipe(tw, tr, func(h *tar.Header) bool {
			if i := strings.Index(h.Name, "/"); i != -1 {
				h.Name = h.Name[i+1:]
			}
			return len(h.Name) > 0
		})
		if err == nil || err == io.EOF {
			tw.Flush()
			w.Close()
			glog.V(5).Infof("Snapshot rewritten from %s", path)
			return
		}
		glog.V(5).Infof("Snapshot of %s failed: %v", path, err)
		w.CloseWithError(err)
	}()

	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	out, err := archive.Tar(path, archive.Uncompressed)
	if _, err := io.Copy(w, out); err != nil {
		return "", err
	}
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Restore ensures the paths managed by t exactly match the container. This requires running
// exec as a user that can delete contents from the container. It will return an error if
// any client operation fails.
func (t *ContainerVolumeTracker) Restore() error {
	if t == nil {
		return nil
	}
	for dest, archivePath := range t.paths {
		if len(archivePath) == 0 {
			return fmt.Errorf("path %s does not have an archive and cannot be restored", dest)
		}
		glog.V(4).Infof("Restoring contents of %s from %s", dest, archivePath)
		if !strings.HasSuffix(dest, "/") {
			dest = dest + "/"
		}

		cmd := exec.Command("/bin/sh", []string{"-c", "rm -rf $@", "", dest + "*"}...)
		_, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("unable to clear preserved path %s: %v", dest, err)
		}

		err = func() error {
			f, err := os.Open(archivePath)
			if err != nil {
				return fmt.Errorf("unable to open archive %s for preserved path %s: %v", archivePath, dest, err)
			}
			defer f.Close()

			if err := archive.Untar(f, dest, nil); err != nil {
				return fmt.Errorf("unable to upload preserved contents from %s to %s: %v", archivePath, dest, err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
