package engine

import "strconv"

// guardRun builds the run flags and the guard command shared by wslc and apple:
// sandboxinit as root entrypoint with the caps guard needs, the workload behind
// the relay, dropped to s.UID/s.GID (default 1000).
func guardRun(s Spec, helper string, va []string, host string, port int) (runArgs, args []string) {
	uid, gid := s.UID, s.GID
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	runArgs = []string{
		"--rm",
		"--cap-add", "SYS_ADMIN", // CLONE_NEWNET
		"--cap-add", "NET_ADMIN", // bring lo up in the new netns
		"--user", "0",
		"-v", helper + ":/sandboxinit:ro",
		"--entrypoint", "/sandboxinit",
	}
	runArgs = append(runArgs, va...)
	runArgs = append(runArgs, proxyEnv("http://"+relayListen)...)
	if s.Interactive {
		runArgs = append(runArgs, "-it")
	}
	if s.Name != "" {
		runArgs = append(runArgs, "--name", s.Name)
	}
	args = []string{
		"guard",
		"--host", host,
		"--port", strconv.Itoa(port),
		"--listen", relayListen,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--",
	}
	return runArgs, append(args, s.Cmd...)
}
