package mocks

// Names for the generated records.
var (
	tokenNames = []string{
		"laptop-sharon", "nas-garage", "office-desktop", "rpi-weather", "build-server",
		"media-center", "camera-front", "camera-back", "homelab-k3s", "printer-3d",
		"router-lab", "dev-vm", "backup-box", "game-server", "home-assistant",
		"solar-monitor", "git-mirror", "ci-runner", "grafana-host", "vpn-gateway",
	}
	tokenDescriptions = []string{
		"Personal laptop, SSH and dev servers", "Garage NAS web UI", "Office workstation",
		"Weather station dashboard", "Build machine, SSH only",
	}
	tunnelPrefixes = []string{"ssh", "web", "api", "grafana", "nas", "cam", "db", "git", "vnc", "mqtt"}
	siteNames      = []string{"shop", "blog", "wiki", "status", "photos", "docs", "api", "portal"}
	agentVersions  = []string{"v1.6.2", "v1.6.1", "v1.5.0", "v1.4.3"}
	agentOS        = []string{"linux", "darwin", "windows", "linux"}
	agentArch      = []string{"amd64", "arm64", "amd64", "arm"}
	publicIPs      = []string{"203.0.113.10", "198.51.100.23", "192.0.2.77", "203.0.113.54", "198.51.100.9"}
	emailTargets   = []string{"ops@example.test", "oncall@example.test", "sharon@example.test"}
	webhookTargets = []string{"https://hooks.example.test/l8tunnel", "https://chat.example.test/webhook/ops"}
)
