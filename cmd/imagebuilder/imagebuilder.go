package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/builder/dockerfile/parser"
	"github.com/docker/docker/pkg/archive"
	dockertypes "github.com/docker/engine-api/types"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"

	"github.com/openshift/imagebuilder"
	"github.com/openshift/imagebuilder/container"
	"github.com/openshift/imagebuilder/dockerclient"
)

func main() {
	log.SetFlags(0)
	defer glog.Flush()
	options := dockerclient.NewClientExecutor(nil)
	var tags stringSliceFlag
	var dockerfilePath string
	var imageFrom string
	var mountSpecs stringSliceFlag
	var inContainer string
	var containerBinary string

	flag.Set("logtostderr", "true")
	flag.Var(&tags, "t", "The name to assign this image, if any. May be specified multiple times.")
	flag.Var(&tags, "tag", "The name to assign this image, if any. May be specified multiple times.")
	flag.StringVar(&dockerfilePath, "f", dockerfilePath, "An optional path to a Dockerfile to use. You may pass multiple docker files using the operating system delimiter.")
	flag.StringVar(&dockerfilePath, "file", dockerfilePath, "An optional path to a Dockerfile to use. You may pass multiple docker files using the operating system delimiter.")
	flag.StringVar(&imageFrom, "from", imageFrom, "An optional FROM to use instead of the one in the Dockerfile.")
	flag.Var(&mountSpecs, "mount", "An optional list of files and directories to mount during the build. Use SRC:DST syntax for each path.")
	flag.BoolVar(&options.AllowPull, "allow-pull", true, "Pull the images that are not present.")
	flag.BoolVar(&options.IgnoreUnrecognizedInstructions, "ignore-unrecognized-instructions", true, "If an unrecognized Docker instruction is encountered, warn but do not fail the build.")
	flag.BoolVar(&options.StrictVolumeOwnership, "strict-volume-ownership", false, "Due to limitations in docker `cp`, owner permissions on volumes are lost. This flag will fail builds that might be affected.")
	flag.StringVar(&inContainer, "container", "", "When set to 'true', run the build inside of a docker container.")
	flag.StringVar(&containerBinary, "container-bin", os.Args[0], "If running inside a container, the path to the appropriate binary")

	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Fatalf("You must provide one argument, the name of a directory to build")
	}

	options.Directory = args[0]
	if len(tags) > 0 {
		options.Tag = tags[0]
		options.AdditionalTags = tags[1:]
	}
	if len(dockerfilePath) == 0 {
		dockerfilePath = filepath.Join(options.Directory, "Dockerfile")
	}

	var mounts []imagebuilder.Mount
	for _, s := range mountSpecs {
		segments := strings.Split(s, ":")
		if len(segments) != 2 {
			log.Fatalf("--mount must be of the form SOURCE:DEST")
		}
		mounts = append(mounts, imagebuilder.Mount{SourcePath: segments[0], DestinationPath: segments[1]})
	}
	options.TransientMounts = mounts

	options.Out, options.ErrOut = os.Stdout, os.Stderr
	options.AuthFn = func(name string) ([]dockertypes.AuthConfig, bool) {
		return nil, false
	}
	options.LogFn = func(format string, args ...interface{}) {
		if glog.V(2) {
			log.Printf("Builder: "+format, args...)
		} else {
			fmt.Fprintf(options.ErrOut, "--> %s\n", fmt.Sprintf(format, args...))
		}
	}

	// Accept ARGS on the command line
	arguments := make(map[string]string)

	dockerfiles := filepath.SplitList(dockerfilePath)
	if len(dockerfiles) == 0 {
		dockerfiles = []string{filepath.Join(options.Directory, "Dockerfile")}
	}

	if err := options.DefaultExcludes(); err != nil {
		log.Fatal(fmt.Errorf("error: Could not parse default .dockerignore: %v", err).Error())
	}

	switch inContainer {
	case "init":
		e := &container.Executor{
			Directory:                      options.Directory,
			Excludes:                       options.Excludes,
			IgnoreUnrecognizedInstructions: options.IgnoreUnrecognizedInstructions,
			TransientMounts:                options.TransientMounts,
			Out:                            options.Out,
			ErrOut:                         options.ErrOut,
			LogFn:                          options.LogFn,
		}
		if err := build(dockerfiles[0], dockerfiles[1:], arguments, imageFrom, options.ErrOut, e); err != nil {
			log.Fatal(err.Error())
		}
	case "true":
		client, err := docker.NewClientFromEnv()
		if err != nil {
			log.Fatal(fmt.Errorf("error: No connection to Docker available: %v", err).Error())
		}
		options.Client = client
		if err := launchBuild(containerBinary, dockerfiles[0], dockerfiles[1:], arguments, imageFrom, options.ErrOut, options); err != nil {
			log.Fatal(fmt.Sprintf("error: %v", err.Error()))
		}
	case "":
		client, err := docker.NewClientFromEnv()
		if err != nil {
			log.Fatal(fmt.Errorf("error: No connection to Docker available: %v", err).Error())
		}
		options.Client = client
		if err := build(dockerfiles[0], dockerfiles[1:], arguments, imageFrom, options.ErrOut, options); err != nil {
			log.Fatal(fmt.Sprintf("error: %v", err.Error()))
		}

	default:
		log.Fatal(fmt.Errorf("error: only 'true', 'init', and '' are valid values for --container").Error())
	}
}

type executor interface {
	Release() []error
	Prepare(b *imagebuilder.Builder, node *parser.Node, from string) error
	Execute(b *imagebuilder.Builder, node *parser.Node) error
	Commit(b *imagebuilder.Builder) error
}

func build(dockerfile string, additionalDockerfiles []string, arguments map[string]string, from string, errOut io.Writer, e executor) error {
	// TODO: handle signals
	defer func() {
		for _, err := range e.Release() {
			fmt.Fprintf(errOut, "Unable to clean up build: %v\n", err)
		}
	}()

	b, node, err := imagebuilder.NewBuilderForFile(dockerfile, arguments)
	if err != nil {
		return err
	}
	if err := e.Prepare(b, node, from); err != nil {
		return err
	}
	if err := e.Execute(b, node); err != nil {
		return err
	}

	for _, s := range additionalDockerfiles {
		_, node, err := imagebuilder.NewBuilderForFile(s, arguments)
		if err != nil {
			return err
		}
		if err := e.Execute(b, node); err != nil {
			return err
		}
	}

	return e.Commit(b)
}

func launchBuild(containerBinary string, dockerfile string, additionalDockerfiles []string, arguments map[string]string, from string, errOut io.Writer, e *dockerclient.ClientExecutor) error {
	// TODO: handle signals
	defer func() {
		for _, err := range e.Release() {
			fmt.Fprintf(errOut, "unable to clean up build: %v\n", err)
		}
	}()

	// parse all docker files and create the unified dockerfile and builder
	b, node, err := imagebuilder.NewBuilderForFile(dockerfile, arguments)
	if err != nil {
		return err
	}
	if err := e.PrepareImage(b, node, from); err != nil {
		return err
	}
	for _, s := range additionalDockerfiles {
		_, add, err := imagebuilder.NewBuilderForFile(s, arguments)
		if err != nil {
			return err
		}
		// silently strip FROM for additional dockerfiles
		node.Children = append(node.Children, imagebuilder.SplitChildren(add, "from")...)
	}

	// check the full dockerfile
	contents := &bytes.Buffer{}
	for _, child := range node.Children {
		step := b.Step()
		if err := step.Resolve(child); err != nil {
			return err
		}
		if err := b.Run(step, imagebuilder.NoopExecutor, true); err != nil {
			return err
		}
		fmt.Fprintln(contents, child.Original)
	}

	glog.V(5).Infof("Final Dockerfile:\n%s", contents.String())
	f, err := ioutil.TempFile("", "imagebuilder-dockerfile")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Close(); err != nil {
		return err
	}
	if err := ioutil.WriteFile(f.Name(), contents.Bytes(), 0600); err != nil {
		return err
	}

	volumeName, _, err := e.AllocateTemporaryVolume()
	if err != nil {
		return err
	}
	opts := docker.CreateContainerOptions{
		Config: &docker.Config{
			Image: b.RunConfig.Image,
		},
		HostConfig: &docker.HostConfig{
			Binds: []string{volumeName + ":/.imagebuilder"},
		},
	}
	opts.Config.Entrypoint = []string{
		"/.imagebuilder/init",
	}
	args := []string{
		fmt.Sprintf("--from=%s", b.RunConfig.Image),
		"-container=init",
		"-file=/.imagebuilder/Dockerfile",
	}
	if v := flag.Lookup("v").Value.String(); v != "" {
		args = append(args, fmt.Sprintf("-v=%s", v))
	}
	opts.Config.Cmd = append(args, "/.imagebuilder/context")

	// copy any source content into the temporary mount path
	// 	if len(e.TransientMounts) > 0 {
	// 		if len(sharedMount) == 0 {
	// 			return fmt.Errorf("no mount point available for temporary mounts")
	// 		}
	// 		binds, err := e.PopulateTransientMounts(opts, e.TransientMounts, sharedMount)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		opts.HostConfig.Binds = append(originalBinds, binds...)
	// 	}

	container, err := e.Client.CreateContainer(opts)
	if err != nil {
		return fmt.Errorf("unable to create build container: %v", err)
	}
	e.Container = container
	e.Deferred = append([]func() error{func() error { return e.RemoveContainer(container.ID) }}, e.Deferred...)

	// copy the build context
	if err := e.CopyContainer(e.Container, e.Excludes, imagebuilder.Copy{Src: []string{"."}, Dest: "/.imagebuilder/context"}); err != nil {
		return err
	}

	// remap both the runtime binary and the generated Dockerfile to their expected paths
	absDockerfile, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}
	absBinary, err := filepath.Abs(containerBinary)
	if err != nil {
		return err
	}
	absDockerfile = imagebuilder.TrimLeadingPath(absDockerfile)
	absBinary = imagebuilder.TrimLeadingPath(absBinary)
	rc, err := archive.TarWithOptions("/", &archive.TarOptions{
		IncludeFiles: []string{absDockerfile, absBinary},
		RebaseNames: map[string]string{
			absDockerfile: "/.imagebuilder/Dockerfile",
			absBinary:     "/.imagebuilder/init",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to create build context: %v", err)
	}
	glog.V(5).Infof("Uploading to %s", container.ID)
	err = e.Client.UploadToContainer(e.Container.ID, docker.UploadToContainerOptions{
		InputStream: rc,
		Path:        "/",
	})
	if err := rc.Close(); err != nil {
		glog.Errorf("Error while closing stream container copy stream %s: %v", container.ID, err)
	}
	if err != nil {
		return err
	}

	cw, err := e.Client.AttachToContainerNonBlocking(docker.AttachToContainerOptions{
		Container:    e.Container.ID,
		Stream:       true,
		OutputStream: e.Out,
		ErrorStream:  e.ErrOut,
		Stdout:       true,
		Stderr:       true,
	})
	if err != nil {
		return fmt.Errorf("unable to attach to container: %v", err)
	}
	if err := e.Client.StartContainer(e.Container.ID, nil); err != nil {
		return fmt.Errorf("unable to start build container: %v", err)
	}
	if err := cw.Wait(); err != nil {
		return fmt.Errorf("unable to stream results from build container: %v", err)
	}
	code, err := e.Client.WaitContainer(e.Container.ID)
	if err != nil {
		return fmt.Errorf("unable to wait for build container to complete: %v", err)
	}
	if code != 0 {
		return fmt.Errorf("build failed, see logs for details (code=%d)", code)
	}

	return e.Commit(b)
}

type stringSliceFlag []string

func (f *stringSliceFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, " ")
}
