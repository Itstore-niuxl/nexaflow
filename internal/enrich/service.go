package enrich

import "strconv"

type ServiceInfo struct {
	Name     string
	Category string
	Risk     string
}

func IdentifyService(port uint16, proto uint8) ServiceInfo {
	portText := strconv.Itoa(int(port))
	if proto == 17 && port == 53 {
		return ServiceInfo{Name: "DNS", Category: "基础网络", Risk: "low"}
	}
	if service, ok := knownServices()[portText]; ok {
		return service
	}
	if port >= 1024 {
		return ServiceInfo{Name: "业务/动态端口", Category: "业务服务", Risk: "observe"}
	}
	return ServiceInfo{Name: "未知服务", Category: "未知", Risk: "observe"}
}

func knownServices() map[string]ServiceInfo {
	return map[string]ServiceInfo{
		"20":    {Name: "FTP Data", Category: "文件传输", Risk: "medium"},
		"21":    {Name: "FTP", Category: "文件传输", Risk: "medium"},
		"22":    {Name: "SSH", Category: "远程管理", Risk: "high"},
		"23":    {Name: "Telnet", Category: "远程管理", Risk: "critical"},
		"25":    {Name: "SMTP", Category: "邮件", Risk: "medium"},
		"53":    {Name: "DNS", Category: "基础网络", Risk: "low"},
		"80":    {Name: "HTTP", Category: "Web", Risk: "low"},
		"110":   {Name: "POP3", Category: "邮件", Risk: "medium"},
		"123":   {Name: "NTP", Category: "基础网络", Risk: "low"},
		"139":   {Name: "NetBIOS", Category: "文件共享", Risk: "high"},
		"143":   {Name: "IMAP", Category: "邮件", Risk: "medium"},
		"389":   {Name: "LDAP", Category: "目录服务", Risk: "high"},
		"443":   {Name: "HTTPS", Category: "Web", Risk: "low"},
		"445":   {Name: "SMB", Category: "文件共享", Risk: "high"},
		"465":   {Name: "SMTPS", Category: "邮件", Risk: "medium"},
		"587":   {Name: "SMTP Submission", Category: "邮件", Risk: "medium"},
		"993":   {Name: "IMAPS", Category: "邮件", Risk: "medium"},
		"995":   {Name: "POP3S", Category: "邮件", Risk: "medium"},
		"1433":  {Name: "SQL Server", Category: "数据库", Risk: "critical"},
		"1521":  {Name: "Oracle", Category: "数据库", Risk: "critical"},
		"3306":  {Name: "MySQL", Category: "数据库", Risk: "critical"},
		"3389":  {Name: "RDP", Category: "远程管理", Risk: "critical"},
		"5432":  {Name: "PostgreSQL", Category: "数据库", Risk: "critical"},
		"5900":  {Name: "VNC", Category: "远程管理", Risk: "critical"},
		"6379":  {Name: "Redis", Category: "缓存", Risk: "critical"},
		"8080":  {Name: "HTTP Alternate", Category: "Web", Risk: "medium"},
		"8081":  {Name: "HTTP Alternate", Category: "Web", Risk: "medium"},
		"8443":  {Name: "HTTPS Alternate", Category: "Web", Risk: "medium"},
		"9200":  {Name: "Elasticsearch", Category: "搜索/数据", Risk: "critical"},
		"11211": {Name: "Memcached", Category: "缓存", Risk: "critical"},
		"27017": {Name: "MongoDB", Category: "数据库", Risk: "critical"},
	}
}
