package main

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

/*
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#define ANCIL_FD_BUFFER(n) \
struct { \
struct cmsghdr h; \
int fd[n]; \
}
int
ancil_send_fds_with_buffer(int sock, const int *fds, unsigned n_fds, void *buffer)
{
struct msghdr msghdr;
char nothing = '!';
struct iovec nothing_ptr;
struct cmsghdr *cmsg;
int i;
nothing_ptr.iov_base = &nothing;
nothing_ptr.iov_len = 1;
msghdr.msg_name = NULL;
msghdr.msg_namelen = 0;
msghdr.msg_iov = &nothing_ptr;
msghdr.msg_iovlen = 1;
msghdr.msg_flags = 0;
msghdr.msg_control = buffer;
msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * n_fds;
cmsg = CMSG_FIRSTHDR(&msghdr);
cmsg->cmsg_len = msghdr.msg_controllen;
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type = SCM_RIGHTS;
for(i = 0; i < n_fds; i++)
((int *)CMSG_DATA(cmsg))[i] = fds[i];
return(sendmsg(sock, &msghdr, 0) >= 0 ? 0 : -1);
}
int
ancil_send_fd(int sock, int fd)
{
ANCIL_FD_BUFFER(1) buffer;
return(ancil_send_fds_with_buffer(sock, &fd, 1, &buffer));
}
void
set_timeout(int sock)
{
struct timeval tv;
tv.tv_sec  = 3;
tv.tv_usec = 0;
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/cmdarg"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"

	vinternet "github.com/xtls/xray-core/transport/internet"
)

var cmdRun = &base.Command{
	UsageLine: "{{.Exec}} run [-c config.json] [-confdir dir]",
	Short:     "Run Xray with config, the default command",
	Long: `
Run Xray with config, the default command.

The -config=file, -c=file flags set the config files for 
Xray. Multiple assign is accepted.

The -confdir=dir flag sets a dir with multiple json config

The -format=json flag sets the format of config files. 
Default "auto".

The -test flag tells Xray to test config files only, 
without launching the server
	`,
}

func init() {
	cmdRun.Run = executeRun // break init loop
}

var (
	configFiles cmdarg.Arg // "Config file for Xray.", the option is customed type, parse in main
	configDir   string
	test        = cmdRun.Flag.Bool("test", false, "Test config file only, without launching Xray server.")
	format      = cmdRun.Flag.String("format", "auto", "Format of input file.")

	/* We have to do this here because Golang's Test will also need to parse flag, before
	 * main func in this file is run.
	 */
	_ = func() bool {
		cmdRun.Flag.Var(&configFiles, "config", "Config path for Xray.")
		cmdRun.Flag.Var(&configFiles, "c", "Short alias of -config")
		cmdRun.Flag.StringVar(&configDir, "confdir", "", "A dir with multiple json config")

		return true
	}()
)

func executeRun(cmd *base.Command, args []string) {
	printVersion()
	server, err := startXray()
	if err != nil {
		fmt.Println("Failed to start:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	if *test {
		fmt.Println("Configuration OK.")
		os.Exit(0)
	}

	if err := server.Start(); err != nil {
		fmt.Println("Failed to start:", err)
		os.Exit(-1)
	}
	defer server.Close()

	/*
		conf.FileCache = nil
		conf.IPCache = nil
		conf.SiteCache = nil
	*/

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	debug.FreeOSMemory()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func fileExists(file string) bool {
	info, err := os.Stat(file)
	return err == nil && !info.IsDir()
}

func dirExists(file string) bool {
	if file == "" {
		return false
	}
	info, err := os.Stat(file)
	return err == nil && info.IsDir()
}

func getRegepxByFormat() string {
	switch strings.ToLower(*format) {
	case "json":
		return `^.+\.(json|jsonc)$`
	case "toml":
		return `^.+\.toml$`
	case "yaml", "yml":
		return `^.+\.(yaml|yml)$`
	default:
		return `^.+\.(json|jsonc|toml|yaml|yml)$`
	}
}

func readConfDir(dirPath string) {
	confs, err := os.ReadDir(dirPath)
	if err != nil {
		log.Fatalln(err)
	}
	for _, f := range confs {
		matched, err := regexp.MatchString(getRegepxByFormat(), f.Name())
		if err != nil {
			log.Fatalln(err)
		}
		if matched {
			configFiles.Set(path.Join(dirPath, f.Name()))
		}
	}
}

func getConfigFilePath() cmdarg.Arg {
	if dirExists(configDir) {
		log.Println("Using confdir from arg:", configDir)
		readConfDir(configDir)
	} else if envConfDir := platform.GetConfDirPath(); dirExists(envConfDir) {
		log.Println("Using confdir from env:", envConfDir)
		readConfDir(envConfDir)
	}

	if len(configFiles) > 0 {
		return configFiles
	}

	if workingDir, err := os.Getwd(); err == nil {
		configFile := filepath.Join(workingDir, "config.json")
		if fileExists(configFile) {
			log.Println("Using default config: ", configFile)
			return cmdarg.Arg{configFile}
		}
	}

	if configFile := platform.GetConfigurationPath(); fileExists(configFile) {
		log.Println("Using config from env: ", configFile)
		return cmdarg.Arg{configFile}
	}

	log.Println("Using config from STDIN")
	return cmdarg.Arg{"stdin:"}
}

func getConfigFormat() string {
	f := core.GetFormatByExtension(*format)
	if f == "" {
		f = "auto"
	}
	return f
}

func ControlOnConnSetup(network string, address string, s uintptr) error {
	fd := int(s)
	path := "protect_path"

	socket, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(err)
		return err
	}

	defer syscall.Close(socket)

	C.set_timeout(C.int(socket))

	err = syscall.Connect(socket, &syscall.SockaddrUnix{Name: path})
	if err != nil {
		log.Println(err)
		return err
	}

	C.ancil_send_fd(C.int(socket), C.int(fd))

	dummy := []byte{1}
	n, err := syscall.Read(socket, dummy)
	if err != nil {
		log.Println(err)
		return err
	}
	if n != 1 || dummy[0] != 0 {
		err := fmt.Errorf("failed to protect fd: %d", fd)
		return err
	}

	return nil
}

func registerControlFunc() {
	err := vinternet.RegisterDialerController(ControlOnConnSetup)
	if err != nil {
		return
	}
	err = vinternet.RegisterListenerController(ControlOnConnSetup)
	if err != nil {
		return
	}
}

func startXray() (core.Server, error) {
	registerControlFunc()
	configFiles := getConfigFilePath()

	// config, err := core.LoadConfig(getConfigFormat(), configFiles[0], configFiles)

	c, err := core.LoadConfig(getConfigFormat(), configFiles)
	if err != nil {
		return nil, newError("failed to load config files: [", configFiles.String(), "]").Base(err)
	}

	server, err := core.New(c)
	if err != nil {
		return nil, newError("failed to create server").Base(err)
	}

	return server, nil
}
