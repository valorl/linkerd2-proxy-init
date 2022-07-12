package iptables

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Configurator struct {
	iptablesBin     string
	iptablesSaveBin string
}

func IPv4() Configurator {
	return Configurator{
		iptablesBin:     "iptables",
		iptablesSaveBin: "iptables-save",
	}
}

func IPv6() Configurator {
	return Configurator{
		iptablesBin:     "ip6tables",
		iptablesSaveBin: "ip6tables-save",
	}
}

func (c Configurator) ConfigureFirewall(firewallConfiguration FirewallConfiguration) error {
	log.Debugf("tracing script execution as [%s]", ExecutionTraceID)

	b := bytes.Buffer{}
	if err := c.executeCommand(firewallConfiguration, c.makeShowAllRules(), &b); err != nil {
		log.Error("aborting firewall configuration")
		return err
	}

	commands := make([]*exec.Cmd, 0)

	matches := chainRegex.FindAllString(b.String(), 1)
	if len(matches) > 0 {
		log.Infof("skipping iptables setup: found %d existing chains", len(matches))
		log.Debugf("matching chains: %v", matches)
		return nil
	}

	commands = c.addIncomingTrafficRules(commands, firewallConfiguration)

	commands = c.addOutgoingTrafficRules(commands, firewallConfiguration)

	for _, cmd := range commands {
		if err := c.executeCommand(firewallConfiguration, cmd, nil); err != nil {
			return err
		}
	}

	_ = c.executeCommand(firewallConfiguration, c.makeShowAllRules(), nil)

	return nil
}

func (c Configurator) addIncomingTrafficRules(commands []*exec.Cmd, firewallConfiguration FirewallConfiguration) []*exec.Cmd {
	commands = append(commands, c.makeCreateNewChain(redirectChainName, "redirect-common-chain"))
	commands = c.addRulesForIgnoredPorts(firewallConfiguration.InboundPortsToIgnore, redirectChainName, commands)
	commands = c.addRulesForIgnoredSubnets(firewallConfiguration.SubnetsToIgnore, redirectChainName, commands)
	commands = c.addRulesForInboundPortRedirect(firewallConfiguration, redirectChainName, commands)

	// Redirect all remaining inbound traffic to the proxy.
	commands = append(
		commands,
		c.makeJumpFromChainToAnotherForAllProtocols(
			IptablesPreroutingChainName,
			redirectChainName,
			"install-proxy-init-prerouting",
			false))

	return commands
}

func (c Configurator) addOutgoingTrafficRules(commands []*exec.Cmd, firewallConfiguration FirewallConfiguration) []*exec.Cmd {
	commands = append(commands, c.makeCreateNewChain(outputChainName, "redirect-common-chain"))

	// Ignore traffic from the proxy
	if firewallConfiguration.ProxyUID > 0 {
		commands = append(commands, c.makeIgnoreUserID(outputChainName, firewallConfiguration.ProxyUID, "ignore-proxy-user-id"))
	}

	// Ignore loopback
	commands = append(commands, c.makeIgnoreLoopback(outputChainName, "ignore-loopback"))
	// Ignore ports
	commands = c.addRulesForIgnoredPorts(firewallConfiguration.OutboundPortsToIgnore, outputChainName, commands)

	commands = append(commands, c.makeRedirectChainToPort(outputChainName, firewallConfiguration.ProxyOutgoingPort, "redirect-all-outgoing-to-proxy-port"))

	// Redirect all remaining outbound traffic to the proxy.
	commands = append(
		commands,
		c.makeJumpFromChainToAnotherForAllProtocols(
			IptablesOutputChainName,
			outputChainName,
			"install-proxy-init-output",
			false))

	return commands
}

func (c Configurator) addRulesForInboundPortRedirect(firewallConfiguration FirewallConfiguration, chainName string, commands []*exec.Cmd) []*exec.Cmd {
	if firewallConfiguration.Mode == RedirectAllMode {
		// Create a new chain for redirecting inbound and outbound traffic to the proxy port.
		commands = append(commands, c.makeRedirectChainToPort(chainName,
			firewallConfiguration.ProxyInboundPort,
			"redirect-all-incoming-to-proxy-port"))
	} else if firewallConfiguration.Mode == RedirectListedMode {
		for _, port := range firewallConfiguration.PortsToRedirectInbound {
			commands = append(
				commands,
				c.makeRedirectChainToPortBasedOnDestinationPort(
					chainName,
					port,
					firewallConfiguration.ProxyInboundPort,
					fmt.Sprintf("redirect-port-%d-to-proxy-port", port)))
		}
	}
	return commands
}

func (c Configurator) addRulesForIgnoredPorts(portsToIgnore []string, chainName string, commands []*exec.Cmd) []*exec.Cmd {
	for _, destinations := range makeMultiportDestinations(portsToIgnore) {
		commands = append(commands, c.makeIgnorePorts(chainName, destinations, fmt.Sprintf("ignore-port-%s", strings.Join(destinations, ","))))
	}
	return commands
}

func (c Configurator) addRulesForIgnoredSubnets(subnetsToIgnore []string, chainName string, commands []*exec.Cmd) []*exec.Cmd {
	for _, subnet := range subnetsToIgnore {
		commands = append(commands, c.makeIgnoreSubnet(chainName, subnet, fmt.Sprintf("ignore-subnet-%s", subnet)))
	}
	return commands
}

func (c Configurator) executeCommand(firewallConfiguration FirewallConfiguration, cmd *exec.Cmd, cmdOut io.Writer) error {
	if strings.HasSuffix(cmd.Path, c.iptablesBin) && firewallConfiguration.UseWaitFlag {
		log.Info("'useWaitFlag' set: iptables will wait for xtables to become available")
		cmd.Args = append(cmd.Args, "-w")
	}

	if len(firewallConfiguration.NetNs) > 0 {
		nsenterArgs := []string{fmt.Sprintf("--net=%s", firewallConfiguration.NetNs)}
		originalCmd := strings.Trim(fmt.Sprintf("%v", cmd.Args), "[]")
		originalCmdAsArgs := strings.Split(originalCmd, " ")
		// separate nsenter args from the rest with `--`,
		// only needed for hosts using BusyBox binaries, like k3s
		// see https://github.com/rancher/k3s/issues/1434#issuecomment-629315909
		originalCmdAsArgs = append([]string{"--"}, originalCmdAsArgs...)
		finalArgs := append(nsenterArgs, originalCmdAsArgs...)
		cmd = exec.Command("nsenter", finalArgs...)
	}

	log.Infof("%s", strings.Trim(fmt.Sprintf("%v", cmd.Args), "[]"))

	if firewallConfiguration.SimulateOnly {
		return nil
	}

	out, err := cmd.CombinedOutput()

	if len(out) > 0 {
		log.Infof("%s", out)
	}

	if err != nil {
		return err
	}

	if cmdOut == nil {
		return nil
	}

	_, err = io.WriteString(cmdOut, string(out))
	if err != nil {
		return err
	}

	return nil
}

func (c Configurator) makeIgnoreUserID(chainName string, uid int, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-m", "owner",
		"--uid-owner", strconv.Itoa(uid),
		"-j", "RETURN",
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeCreateNewChain(name string, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-N", name,
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeRedirectChainToPort(chainName string, portToRedirect int, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-p", "tcp",
		"-j", "REDIRECT",
		"--to-port", strconv.Itoa(portToRedirect),
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeIgnorePorts(chainName string, destinations []string, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-p", "tcp",
		"--match", "multiport",
		"--dports", strings.Join(destinations, ","),
		"-j", "RETURN",
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeIgnoreSubnet(chainName string, subnet string, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-p", "all",
		"-j", "RETURN",
		"-s", subnet,
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeIgnoreLoopback(chainName string, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-o", "lo",
		"-j", "RETURN",
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeRedirectChainToPortBasedOnDestinationPort(chainName string, destinationPort int, portToRedirect int, comment string) *exec.Cmd {
	return exec.Command(c.iptablesBin,
		"-t", "nat",
		"-A", chainName,
		"-p", "tcp",
		"--destination-port", strconv.Itoa(destinationPort),
		"-j", "REDIRECT",
		"--to-port", strconv.Itoa(portToRedirect),
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeJumpFromChainToAnotherForAllProtocols(
	chainName string, targetChain string, comment string, delete bool,
) *exec.Cmd {
	action := "-A"
	if delete {
		action = "-D"
	}

	return exec.Command(c.iptablesBin,
		"-t", "nat",
		action, chainName,
		"-j", targetChain,
		"-m", "comment",
		"--comment", formatComment(comment))
}

func (c Configurator) makeShowAllRules() *exec.Cmd {
	return exec.Command(c.iptablesSaveBin, "-t", "nat")
}
