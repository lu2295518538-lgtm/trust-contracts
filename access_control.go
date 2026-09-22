// access_control.go —— 任务二阶段D：畜牧数据授权共享 · 链上策略执行合约
//
// 定位（对应申报书句 27/28/30/32/34）：
//   把阶段B的本地 PDP 决策上链，形成"请求事务 → 合约自动触发 → 授权/拒绝"的自动化闭环。
//   本合约是**第二道防线**：链下 PolicyEngine 毫秒级快判在前，链上合约不可篡改终判在后。
//
// 三条链（同一合约内以 key 前缀分区，便于单合约治理）：
//   ① 目录链 DirectoryChain  key = dir:<data_did>        —— 只存元数据（分类/级别/字段级敏感度），绝不存原文
//   ② 授权链 AuthChain       key = auth:<data_did>:<sub> —— 授权记录（字段集/时效/用途/vc_hash/状态）
//   ③ 日志链 LogChain        key = log:<data_did>:<seq>  —— 只存行为（谁/何时/何动作/哪些字段标签）
//
// 隐私纪律（§1.4 句 33–35）：
//   链上**只存行为与摘要**，不存 PII、不存字段值、不存原文。字段仅以"字段名标签"出现。
//
// 组合语义（防止链上裁决被误用来放权）：
//   最终决策 = 链下 PDP 决策 ∩ 链上合约决策。链上只能"进一步收紧"（deny 或缩小 granted_fields），
//   永远不能把链下的 deny 翻转成 allow —— 与"就高从严 / 默认 deny 显式 allow"纪律一致。
//
// 治理：合约含 version + 多签升级（proposeUpgrade / approveUpgrade），升级需达到 admin 阈值。
//
// 构建（在 VM 上执行）：
//   GOOS=js GOARCH=wasm go build -o access_control.wasm access_control.go
//   或按 ChainMaker docker-go 方式打包，再用 cmc client contract user create 部署。

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

const (
	contractVersion = "1.0.0"

	prefixDir     = "dir_"
	prefixAuth    = "auth_"
	prefixLog     = "log_"
	prefixLogSeq  = "logseq_"
	prefixAdmin   = "admin_"
	keyAdminQuota = "admin_quota"
	keyUpgrade    = "upgrade_proposal"

	// 动作类型：与链下 core/access_log.py ACTION_TYPES 保持一致
	actRetrieve  = "RETRIEVE"
	actReqAuth   = "AUTHORIZE_REQUEST"
	actGrant     = "AUTHORIZE_GRANT"
	actRevoke    = "AUTHORIZE_REVOKE"
	actAccess    = "DATA_ACCESS"
	actDeny      = "DATA_DENY"
)

// DirEntry 目录链条目：只有"有什么数据"，没有"数据是什么"
type DirEntry struct {
	DataDid        string            `json:"data_did"`
	OwnerDid       string            `json:"owner_did"`
	Classification string            `json:"classification"`
	Level          string            `json:"level"`            // L1..L4
	FieldLevels    map[string]string `json:"field_levels"`     // {字段名: L1..L4}，仅标签，无值
	UpdatedAt      string            `json:"updated_at"`
}

// AuthRecord 授权链条目：链下签发 VC，链上存哈希与范围摘要（§0.3.1 表 C 桥接设计）
type AuthRecord struct {
	OwnerDid   string   `json:"owner_did"`
	SubjectDid string   `json:"subject_did"`
	DataDid    string   `json:"data_did"`
	Fields     []string `json:"fields"`
	Purpose    string   `json:"purpose"`
	ExpireAt   int64    `json:"expire_at"` // Unix 秒；0 表示不限（不推荐）
	Operations []string `json:"operations"`
	VcHash     string   `json:"vc_hash"`
	Status     string   `json:"status"` // active | revoked
	GrantedAt  int64    `json:"granted_at"`
	RevokedAt  int64    `json:"revoked_at"`
}

// LogEntry 日志链条目：只存行为
type LogEntry struct {
	Seq       int64    `json:"seq"`
	DataDid   string   `json:"data_did"`
	ActorDid  string   `json:"actor_did"`
	Action    string   `json:"action"`
	Fields    []string `json:"fields"` // 仅字段名标签
	Purpose   string   `json:"purpose"`
	Effect    string   `json:"effect"`
	Reason    string   `json:"reason"`
	ProofHash string   `json:"proof_hash"` // vc_hash / env_hash 等摘要
	Ts        int64    `json:"ts"`
}

// Decision 合约终判结果
type Decision struct {
	Allowed       bool     `json:"allowed"`
	Level         string   `json:"level"`
	GrantedFields []string `json:"granted_fields"`
	Reason        string   `json:"reason"`
	Path          string   `json:"path"` // fast | full
	TxTs          int64    `json:"tx_ts"`
	Version       string   `json:"version"`
}

type AccessControlContract struct{}

// ---------------------------------------------------------------- 生命周期

func (c *AccessControlContract) InitContract() protogo.Response {
	args := sdk.Instance.GetArgs()
	// 初始化管理员集合与多签阈值（治理：合约可升级，但需多签）
	admins := string(args["admins"]) // 逗号分隔的 DID
	quota := string(args["quota"])
	if quota == "" {
		quota = "2"
	}
	if admins != "" {
		for _, a := range strings.Split(admins, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				_ = sdk.Instance.PutStateByte(prefixAdmin+safeKey(a), "", []byte("1"))
			}
		}
	}
	_ = sdk.Instance.PutStateByte(keyAdminQuota, "", []byte(quota))
	sdk.Instance.Infof("access_control initialized, version=%s quota=%s", contractVersion, quota)
	return sdk.Success([]byte("init ok, version=" + contractVersion))
}

func (c *AccessControlContract) UpgradeContract() protogo.Response {
	// 升级须先经 proposeUpgrade + 足额 approveUpgrade（多签治理）
	raw, err := sdk.Instance.GetStateByte(keyUpgrade, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("升级被拒绝：无有效升级提案（需先 proposeUpgrade 并达到多签阈值）")
	}
	var p map[string]interface{}
	if e := json.Unmarshal(raw, &p); e != nil {
		return sdk.Error("升级提案解析失败")
	}
	approvals, _ := p["approvals"].(float64)
	quota := c.adminQuota()
	if int(approvals) < quota {
		return sdk.Error("升级被拒绝：批准数 " + strconv.Itoa(int(approvals)) + " < 阈值 " + strconv.Itoa(quota))
	}
	_ = sdk.Instance.DelState(keyUpgrade, "")
	sdk.Instance.Infof("access_control upgraded to %s", contractVersion)
	return sdk.Success([]byte("upgrade ok, version=" + contractVersion))
}

func (c *AccessControlContract) InvokeContract(method string) protogo.Response {
	switch method {
	case "registerData":
		return c.registerData()
	case "grantAuthorization":
		return c.grantAuthorization()
	case "revokeAuthorization":
		return c.revokeAuthorization()
	case "requestAccess":
		return c.requestAccess()
	case "queryAuthorization":
		return c.queryAuthorization()
	case "queryDirectory":
		return c.queryDirectory()
	case "queryLog":
		return c.queryLog()
	case "recordLog":
		return c.recordLog()
	case "proposeUpgrade":
		return c.proposeUpgrade()
	case "approveUpgrade":
		return c.approveUpgrade()
	case "version":
		return sdk.Success([]byte(contractVersion))
	default:
		return sdk.Error("未知方法: " + method)
	}
}

// ---------------------------------------------------------------- 目录链

// registerData 登记/更新目录链条目（元数据，无原文）
func (c *AccessControlContract) registerData() protogo.Response {
	a := sdk.Instance.GetArgs()
	dataDid := string(a["data_did"])
	if dataDid == "" {
		return sdk.Error("data_did 必填")
	}
	e := DirEntry{
		DataDid:        dataDid,
		OwnerDid:       string(a["owner_did"]),
		Classification: string(a["classification"]),
		Level:          normLevel(string(a["level"])),
		FieldLevels:    map[string]string{},
		UpdatedAt:      strconv.FormatInt(c.txTs(), 10),
	}
	if fl := string(a["field_levels"]); fl != "" {
		_ = json.Unmarshal([]byte(fl), &e.FieldLevels)
	}
	b, _ := json.Marshal(e)
	if err := sdk.Instance.PutStateByte(prefixDir+safeKey(dataDid), "", b); err != nil {
		return sdk.Error("目录链写入失败: " + err.Error())
	}
	return sdk.Success(b)
}

func (c *AccessControlContract) queryDirectory() protogo.Response {
	dataDid := string(sdk.Instance.GetArgs()["data_did"])
	b, err := sdk.Instance.GetStateByte(prefixDir+safeKey(dataDid), "")
	if err != nil || len(b) == 0 {
		return sdk.Error("目录链无此数据: " + dataDid)
	}
	return sdk.Success(b)
}

// ---------------------------------------------------------------- 授权链

// grantAuthorization 授权上链存证（由授权方签名提交；链上只存范围摘要 + vc_hash）
func (c *AccessControlContract) grantAuthorization() protogo.Response {
	a := sdk.Instance.GetArgs()
	dataDid := string(a["data_did"])
	subject := string(a["subject_did"])
	owner := string(a["owner_did"])
	if dataDid == "" || subject == "" || owner == "" {
		return sdk.Error("data_did / subject_did / owner_did 必填")
	}
	// 越权保护：只有目录链登记的 owner 可授权该数据
	dir, ok := c.getDir(dataDid)
	if ok && dir.OwnerDid != "" && dir.OwnerDid != owner {
		c.appendLog(dataDid, owner, actDeny, nil, "", "deny", "非数据所有者尝试授权", "")
		return sdk.Error("仅数据所有者可签发该数据授权")
	}
	rec := AuthRecord{
		OwnerDid:   owner,
		SubjectDid: subject,
		DataDid:    dataDid,
		Fields:     splitCSV(string(a["fields"])),
		Purpose:    string(a["purpose"]),
		ExpireAt:   parseInt(string(a["expire_at"])),
		Operations: splitCSV(string(a["operations"])),
		VcHash:     string(a["vc_hash"]),
		Status:     "active",
		GrantedAt:  c.txTs(),
	}
	if len(rec.Fields) == 0 {
		return sdk.Error("fields 必填（最小必要原则）")
	}
	if rec.Purpose == "" {
		return sdk.Error("purpose 必填（用途限定）")
	}
	if len(rec.Operations) == 0 {
		rec.Operations = []string{"read"}
	}
	b, _ := json.Marshal(rec)
	if err := sdk.Instance.PutStateByte(prefixAuth+safeKey(dataDid)+"_"+safeKey(subject), "", b); err != nil {
		return sdk.Error("授权链写入失败: " + err.Error())
	}
	c.appendLog(dataDid, owner, actGrant, rec.Fields, rec.Purpose, "allow", "授权签发", rec.VcHash)
	return sdk.Success(b)
}

func (c *AccessControlContract) revokeAuthorization() protogo.Response {
	a := sdk.Instance.GetArgs()
	dataDid := string(a["data_did"])
	subject := string(a["subject_did"])
	key := prefixAuth + safeKey(dataDid) + "_" + safeKey(subject)
	raw, err := sdk.Instance.GetStateByte(key, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("无此授权记录")
	}
	var rec AuthRecord
	if e := json.Unmarshal(raw, &rec); e != nil {
		return sdk.Error("授权记录解析失败")
	}
	// 越权保护：只有授权方本人可撤销
	if op := string(a["owner_did"]); op != "" && op != rec.OwnerDid {
		return sdk.Error("仅授权方可撤销该授权")
	}
	rec.Status = "revoked"
	rec.RevokedAt = c.txTs()
	b, _ := json.Marshal(rec)
	_ = sdk.Instance.PutStateByte(key, "", b)
	c.appendLog(dataDid, rec.OwnerDid, actRevoke, rec.Fields, rec.Purpose, "revoked",
		string(a["reason"]), rec.VcHash)
	return sdk.Success(b)
}

func (c *AccessControlContract) queryAuthorization() protogo.Response {
	a := sdk.Instance.GetArgs()
	raw, err := sdk.Instance.GetStateByte(prefixAuth+safeKey(string(a["data_did"]))+"_"+safeKey(string(a["subject_did"])), "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("无此授权记录")
	}
	return sdk.Success(raw)
}

// ---------------------------------------------------------------- 终判（句 30/32）

// requestAccess 合约内重算 decide()：无论 allow/deny 都写日志链（句 32 默认 deny）
func (c *AccessControlContract) requestAccess() protogo.Response {
	a := sdk.Instance.GetArgs()
	dataDid := string(a["data_did"])
	subject := string(a["subject_did"])
	purpose := string(a["purpose"])
	envHash := string(a["env_hash"])
	wanted := splitCSV(string(a["fields"]))
	operation := string(a["operation"])
	if operation == "" {
		operation = "read"
	}

	d := Decision{Allowed: false, GrantedFields: []string{}, TxTs: c.txTs(), Version: contractVersion}

	dir, ok := c.getDir(dataDid)
	if !ok {
		d.Reason = "目录链无此数据，默认拒绝"
		c.appendLog(dataDid, subject, actDeny, wanted, purpose, "deny", d.Reason, envHash)
		return respond(d)
	}
	d.Level = dir.Level

	switch dir.Level {
	case "L1":
		// 公开数据：快速路径，放行全部 L1 字段
		d.Allowed = true
		d.Path = "fast"
		d.GrantedFields = fieldsAtMost(dir.FieldLevels, 1, wanted)
		d.Reason = "L1 公开数据，免授权访问"
	case "L2":
		// 内部数据：需可识别主体，快速路径
		if subject == "" {
			d.Reason = "L2 内部数据需可识别的请求主体"
		} else {
			d.Allowed = true
			d.Path = "fast"
			d.GrantedFields = fieldsAtMost(dir.FieldLevels, 2, wanted)
			d.Reason = "L2 内部数据，主体可识别即放行（非敏感字段）"
		}
	default:
		// L3/L4：完整路径，必须存在有效授权记录
		d.Path = "full"
		raw, err := sdk.Instance.GetStateByte(prefixAuth+safeKey(dataDid)+"_"+safeKey(subject), "")
		if err != nil || len(raw) == 0 {
			d.Reason = "L3/L4 敏感数据：链上无有效授权记录，默认拒绝"
			break
		}
		var rec AuthRecord
		if e := json.Unmarshal(raw, &rec); e != nil {
			d.Reason = "授权记录解析失败"
			break
		}
		if rec.Status != "active" {
			d.Reason = "授权已被撤销"
			break
		}
		if rec.ExpireAt > 0 && c.txTs() > rec.ExpireAt {
			d.Reason = "授权已过期"
			break
		}
		if purpose != "" && rec.Purpose != "" && purpose != rec.Purpose {
			d.Reason = "请求用途「" + purpose + "」超出授权用途「" + rec.Purpose + "」"
			break
		}
		if !contains(rec.Operations, operation) {
			d.Reason = "操作「" + operation + "」不在授权操作集内"
			break
		}
		// 字段级终判：请求字段 ∩ 授权字段（就高从严，绝不外扩）
		granted := intersect(rec.Fields, wanted)
		if len(granted) == 0 {
			d.Reason = "请求字段不在授权范围内"
			break
		}
		if dir.Level == "L4" && string(a["human_approved"]) != "true" {
			d.Reason = "L4 核心数据强制人工审批，缺少 human_approved 标记"
			break
		}
		d.Allowed = true
		d.GrantedFields = granted
		d.Reason = "链上授权记录校验通过"
	}

	if d.Allowed {
		c.appendLog(dataDid, subject, actAccess, d.GrantedFields, purpose, "allow", d.Reason, envHash)
	} else {
		c.appendLog(dataDid, subject, actDeny, wanted, purpose, "deny", d.Reason, envHash)
	}
	return respond(d)
}

// ---------------------------------------------------------------- 日志链

func (c *AccessControlContract) recordLog() protogo.Response {
	a := sdk.Instance.GetArgs()
	e := c.appendLog(string(a["data_did"]), string(a["actor_did"]), string(a["action"]),
		splitCSV(string(a["fields"])), string(a["purpose"]),
		string(a["effect"]), string(a["reason"]), string(a["proof_hash"]))
	b, _ := json.Marshal(e)
	return sdk.Success(b)
}

func (c *AccessControlContract) queryLog() protogo.Response {
	a := sdk.Instance.GetArgs()
	dataDid := string(a["data_did"])
	seq := c.logSeq(dataDid)
	limit := parseInt(string(a["limit"]))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := make([]LogEntry, 0, limit)
	for i := seq; i > 0 && int64(len(out)) < limit; i-- {
		raw, err := sdk.Instance.GetStateByte(prefixLog+safeKey(dataDid)+"_"+strconv.FormatInt(i, 10), "")
		if err != nil || len(raw) == 0 {
			continue
		}
		var e LogEntry
		if json.Unmarshal(raw, &e) == nil {
			out = append(out, e)
		}
	}
	b, _ := json.Marshal(out)
	return sdk.Success(b)
}

func (c *AccessControlContract) appendLog(dataDid, actor, action string, fields []string,
	purpose, effect, reason, proofHash string) LogEntry {
	seq := c.logSeq(dataDid) + 1
	e := LogEntry{
		Seq: seq, DataDid: dataDid, ActorDid: actor, Action: action,
		Fields: fields, Purpose: purpose, Effect: effect, Reason: reason,
		ProofHash: proofHash, Ts: c.txTs(),
	}
	b, _ := json.Marshal(e)
	_ = sdk.Instance.PutStateByte(prefixLog+safeKey(dataDid)+"_"+strconv.FormatInt(seq, 10), "", b)
	_ = sdk.Instance.PutStateByte(prefixLogSeq+safeKey(dataDid), "", []byte(strconv.FormatInt(seq, 10)))
	return e
}

func (c *AccessControlContract) logSeq(dataDid string) int64 {
	raw, err := sdk.Instance.GetStateByte(prefixLogSeq+safeKey(dataDid), "")
	if err != nil || len(raw) == 0 {
		return 0
	}
	return parseInt(string(raw))
}

// ---------------------------------------------------------------- 治理（多签升级）

func (c *AccessControlContract) proposeUpgrade() protogo.Response {
	a := sdk.Instance.GetArgs()
	proposer := string(a["admin_did"])
	if !c.isAdmin(proposer) {
		return sdk.Error("仅管理员可发起升级提案")
	}
	p := map[string]interface{}{
		"target_version": string(a["target_version"]),
		"digest":         string(a["digest"]),
		"proposer":       proposer,
		"approvals":      1,
		"approvers":      []string{proposer},
		"ts":             c.txTs(),
	}
	b, _ := json.Marshal(p)
	_ = sdk.Instance.PutStateByte(keyUpgrade, "", b)
	return sdk.Success(b)
}

func (c *AccessControlContract) approveUpgrade() protogo.Response {
	a := sdk.Instance.GetArgs()
	approver := string(a["admin_did"])
	if !c.isAdmin(approver) {
		return sdk.Error("仅管理员可批准升级")
	}
	raw, err := sdk.Instance.GetStateByte(keyUpgrade, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("无待批准的升级提案")
	}
	var p map[string]interface{}
	if e := json.Unmarshal(raw, &p); e != nil {
		return sdk.Error("提案解析失败")
	}
	approvers := toStrSlice(p["approvers"])
	if contains(approvers, approver) {
		return sdk.Error("该管理员已批准，不可重复计票")
	}
	approvers = append(approvers, approver)
	p["approvers"] = approvers
	p["approvals"] = float64(len(approvers))
	b, _ := json.Marshal(p)
	_ = sdk.Instance.PutStateByte(keyUpgrade, "", b)
	return sdk.Success(b)
}

func (c *AccessControlContract) isAdmin(did string) bool {
	if did == "" {
		return false
	}
	raw, err := sdk.Instance.GetStateByte(prefixAdmin+safeKey(did), "")
	return err == nil && len(raw) > 0
}

func (c *AccessControlContract) adminQuota() int {
	raw, err := sdk.Instance.GetStateByte(keyAdminQuota, "")
	if err != nil || len(raw) == 0 {
		return 2
	}
	q := int(parseInt(string(raw)))
	if q <= 0 {
		return 2
	}
	return q
}

// ---------------------------------------------------------------- 工具

func (c *AccessControlContract) txTs() int64 {
	ts, _ := sdk.Instance.GetTxTimeStamp()
	return parseInt(ts)
}

func (c *AccessControlContract) getDir(dataDid string) (DirEntry, bool) {
	var e DirEntry
	raw, err := sdk.Instance.GetStateByte(prefixDir+safeKey(dataDid), "")
	if err != nil || len(raw) == 0 {
		return e, false
	}
	if json.Unmarshal(raw, &e) != nil {
		return e, false
	}
	return e, true
}

func respond(d Decision) protogo.Response {
	b, _ := json.Marshal(d)
	return sdk.Success(b)
}

func normLevel(l string) string {
	l = strings.ToUpper(strings.TrimSpace(l))
	switch l {
	case "L1", "L2", "L3", "L4":
		return l
	default:
		return "L2" // 未知级别按内部数据从严处理
	}
}

// fieldsAtMost 返回敏感度不超过 maxLevel 的字段（wanted 非空时再取交集）
func fieldsAtMost(fl map[string]string, maxLevel int, wanted []string) []string {
	out := []string{}
	for name, lv := range fl {
		n := 2
		if len(lv) == 2 && lv[0] == 'L' {
			n = int(lv[1] - '0')
		}
		if n <= maxLevel {
			out = append(out, name)
		}
	}
	if len(wanted) > 0 {
		out = intersect(out, wanted)
	}
	return out
}

func intersect(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	out := []string{}
	for _, y := range b {
		if m[y] {
			out = append(out, y)
		}
	}
	return out
}

func contains(a []string, x string) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	// 兼容 JSON 数组与逗号分隔两种传参
	if strings.HasPrefix(strings.TrimSpace(s), "[") {
		var arr []string
		if json.Unmarshal([]byte(s), &arr) == nil {
			return arr
		}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func toStrSlice(v interface{}) []string {
	out := []string{}
	arr, ok := v.([]interface{})
	if !ok {
		return out
	}
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func main() {
	err := sandbox.Start(new(AccessControlContract))
	if err != nil {
		sdk.Instance.Errorf("contract start failed: %v", err)
	}
}

// safeKey 将 DID 等含非法字符的标识转换为 ChainMaker 合法的 state key。
//
// ChainMaker 约束（protocol/v2 vm_interface.go）:
//   DefaultStateRegex     = "^[a-zA-Z0-9._-]+$"   // 冒号 ':' 非法
//   DefaultMaxStateKeyLen = 1024
//
// 而 W3C DID 标准形如 did:cm:data:xxx 必然含冒号，故必须净化。
// 做法：非法字符逐字节替换为 '_'，并追加原串 sha256 前 4 字节的 hex 短哈希，
// 既保留可读性，又避免 "did:cm:x" 与 "did_cm_x" 被映射到同一 key 的碰撞风险
// （符合"就高从严"纪律：宁可多一层防护，也不留可被构造的碰撞面）。
func safeKey(s string) string {
	if s == "" {
		return ""
	}
	b := make([]byte, 0, len(s)+9)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	h := sha256.Sum256([]byte(s))
	return string(b) + "_" + hex.EncodeToString(h[:4])
}
