// standard_manager.go —— 任务三：畜牧产品质量标准管理链上合约
//
// 职责：标准库（参考基准）的链上登记、版本演进、停用与查询。
// 设计为「本地 SQLite 标准库的链上镜像」：链上仅存标准元数据（公开参考基准），
// 不存任何企业原始检测值，符合数据不出域 / 最小够用原则（GB/T 43697-2024）。
//
// 治理：InitContract 写入部署时传入的 admins 集合与多签阈值 quota；
//      add/update/disable 仅 admin 可调（isAdmin 校验）。
//
// 构建（VM）：
//   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o contract_name standard_manager.go
//   7z a -t7z standard_manager.7z contract_name Dockerfile
// 部署：
//   cmc client contract user create --contract-name=standard_manager --version=1.0.0 \
//     --byte-code-path=.../standard_manager.7z --runtime-type=DOCKER_GO \
//     --params='{"admins":"did:cm:org:wx-org1,...","quota":"2"}' --sync-result=true

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

const contractVersion = "1.0.0"

const (
	prefixSM       = "sm_"       // sm:<safeKey(standardId)>:<version>  -> 单版本记录
	prefixSMActive = "sma_"      // sma:<safeKey(standardId)>           -> 当前 active 版本号
	prefixSMIdx    = "sm_idx"    // JSON 数组：所有 standardId（枚举用）
	prefixAdmin    = "admin_"
	keyAdminQuota  = "admin_quota"
)

// Standard 标准记录（链上镜像）
type Standard struct {
	StandardId     string `json:"standard_id"`
	Item           string `json:"item"`
	Category       string `json:"category"`
	Stage          string `json:"stage"`
	JudgeType      string `json:"judge_type"` // threshold | qualitative | enum
	MinLimit       string `json:"min_limit"`
	MaxLimit       string `json:"max_limit"`
	Unit           string `json:"unit"`
	Method         string `json:"method"`
	Basis          string `json:"basis"`
	Version        string `json:"version"`
	Status         string `json:"status"` // active | superseded | revoked
	IssuerDid      string `json:"issuer_did"`
	EffectiveTime  string `json:"effective_time"`
	ExpireTime     string `json:"expire_time"`
	GovernanceNote string `json:"governance_note"`
	CreateTime     string `json:"create_time"`
	UpdateTime     string `json:"update_time"`
}

type StandardManagerContract struct{}

// ---------------------------------------------------------------- 生命周期

func (c *StandardManagerContract) InitContract() protogo.Response {
	args := sdk.Instance.GetArgs()
	admins := string(args["admins"])
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
	sdk.Instance.Infof("standard_manager initialized, version=%s quota=%s", contractVersion, quota)
	return sdk.Success([]byte("init ok, version=" + contractVersion))
}

func (c *StandardManagerContract) UpgradeContract() protogo.Response {
	sdk.Instance.Infof("standard_manager upgraded to %s", contractVersion)
	return sdk.Success([]byte("upgrade ok, version=" + contractVersion))
}

func (c *StandardManagerContract) InvokeContract(method string) protogo.Response {
	switch method {
	case "addStandard":
		return c.addStandard()
	case "updateStandard":
		return c.updateStandard()
	case "disableStandard":
		return c.disableStandard()
	case "getStandard":
		return c.getStandard()
	case "queryStandards":
		return c.queryStandards()
	case "version":
		return sdk.Success([]byte(contractVersion))
	default:
		return sdk.Error("未知方法: " + method)
	}
}

// ---------------------------------------------------------------- 写：登记 / 演进 / 停用

func (c *StandardManagerContract) addStandard() protogo.Response {
	if !c.isAdmin(string(sdk.Instance.GetArgs()["admin_did"])) {
		return sdk.Error("仅管理员可登记标准")
	}
	a := sdk.Instance.GetArgs()
	sid := strings.TrimSpace(string(a["standard_id"]))
	if sid == "" {
		return sdk.Error("standard_id 必填")
	}
	if strings.TrimSpace(string(a["item"])) == "" {
		return sdk.Error("item 必填")
	}
	// 防重复：已存在 active 版本则拒绝（应走 updateStandard 演进新版本）
	if raw, _ := sdk.Instance.GetStateByte(prefixSMActive+safeKey(sid), ""); len(raw) > 0 {
		return sdk.Error("标准 " + sid + " 已存在 active 版本，请走 updateStandard")
	}
	ver := strings.TrimSpace(string(a["version"]))
	if ver == "" {
		ver = "1"
	}
	now := strconv.FormatInt(c.txTs(), 10)
	st := Standard{
		StandardId:     sid,
		Item:           strings.TrimSpace(string(a["item"])),
		Category:       strings.TrimSpace(string(a["category"])),
		Stage:          strings.TrimSpace(string(a["stage"])),
		JudgeType:      strings.TrimSpace(string(a["judge_type"])),
		MinLimit:       strings.TrimSpace(string(a["min_limit"])),
		MaxLimit:       strings.TrimSpace(string(a["max_limit"])),
		Unit:           strings.TrimSpace(string(a["unit"])),
		Method:         strings.TrimSpace(string(a["method"])),
		Basis:          strings.TrimSpace(string(a["basis"])),
		Version:        ver,
		Status:         "active",
		IssuerDid:      strings.TrimSpace(string(a["issuer_did"])),
		EffectiveTime:  strings.TrimSpace(string(a["effective_time"])),
		ExpireTime:     strings.TrimSpace(string(a["expire_time"])),
		GovernanceNote: strings.TrimSpace(string(a["governance_note"])),
		CreateTime:     now,
		UpdateTime:     now,
	}
	b, _ := json.Marshal(st)
	if err := sdk.Instance.PutStateByte(prefixSM+safeKey(sid)+"_"+ver, "", b); err != nil {
		return sdk.Error("标准写入失败: " + err.Error())
	}
	_ = sdk.Instance.PutStateByte(prefixSMActive+safeKey(sid), "", []byte(ver))
	c.appendIdx(sid)
	return sdk.Success(b)
}

// updateStandard 演进新版本：保留历史版本（旧版本置 superseded），指针切到新版本
func (c *StandardManagerContract) updateStandard() protogo.Response {
	if !c.isAdmin(string(sdk.Instance.GetArgs()["admin_did"])) {
		return sdk.Error("仅管理员可演进标准")
	}
	a := sdk.Instance.GetArgs()
	sid := strings.TrimSpace(string(a["standard_id"]))
	if sid == "" {
		return sdk.Error("standard_id 必填")
	}
	activeVer := c.activeVersion(sid)
	if activeVer == "" {
		return sdk.Error("标准 " + sid + " 不存在，无法更新")
	}
	raw, err := sdk.Instance.GetStateByte(prefixSM+safeKey(sid)+"_"+activeVer, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("标准 " + sid + " 当前版本记录缺失")
	}
	var cur Standard
	if e := json.Unmarshal(raw, &cur); e != nil {
		return sdk.Error("当前版本解析失败")
	}
	// 新版本号 = 旧版本数值 + 1
	oldN := parseInt(activeVer)
	newVer := strconv.FormatInt(oldN+1, 10)
	// 覆盖：传入则取传入，否则沿用当前
	now := strconv.FormatInt(c.txTs(), 10)
	cur.Version = newVer
	if v := strings.TrimSpace(string(a["item"])); v != "" {
		cur.Item = v
	}
	if v := strings.TrimSpace(string(a["category"])); v != "" {
		cur.Category = v
	}
	if v := strings.TrimSpace(string(a["stage"])); v != "" {
		cur.Stage = v
	}
	if v := strings.TrimSpace(string(a["judge_type"])); v != "" {
		cur.JudgeType = v
	}
	if v := strings.TrimSpace(string(a["min_limit"])); v != "" {
		cur.MinLimit = v
	}
	if v := strings.TrimSpace(string(a["max_limit"])); v != "" {
		cur.MaxLimit = v
	}
	if v := strings.TrimSpace(string(a["unit"])); v != "" {
		cur.Unit = v
	}
	if v := strings.TrimSpace(string(a["method"])); v != "" {
		cur.Method = v
	}
	if v := strings.TrimSpace(string(a["basis"])); v != "" {
		cur.Basis = v
	}
	if v := strings.TrimSpace(string(a["issuer_did"])); v != "" {
		cur.IssuerDid = v
	}
	if v := strings.TrimSpace(string(a["effective_time"])); v != "" {
		cur.EffectiveTime = v
	}
	if v := strings.TrimSpace(string(a["expire_time"])); v != "" {
		cur.ExpireTime = v
	}
	if v := strings.TrimSpace(string(a["governance_note"])); v != "" {
		cur.GovernanceNote = v
	}
	cur.Status = "active"
	cur.UpdateTime = now

	b, _ := json.Marshal(cur)
	if err := sdk.Instance.PutStateByte(prefixSM+safeKey(sid)+"_"+newVer, "", b); err != nil {
		return sdk.Error("新版本写入失败: " + err.Error())
	}
	// 旧版本置 superseded
	cur.Status = "superseded"
	oldB, _ := json.Marshal(cur)
	_ = sdk.Instance.PutStateByte(prefixSM+safeKey(sid)+"_"+activeVer, "", oldB)
	_ = sdk.Instance.PutStateByte(prefixSMActive+safeKey(sid), "", []byte(newVer))
	return sdk.Success(b)
}

// disableStandard 停用：当前 active 版本状态置 revoked（历史版本保留）
func (c *StandardManagerContract) disableStandard() protogo.Response {
	if !c.isAdmin(string(sdk.Instance.GetArgs()["admin_did"])) {
		return sdk.Error("仅管理员可停用标准")
	}
	a := sdk.Instance.GetArgs()
	sid := strings.TrimSpace(string(a["standard_id"]))
	if sid == "" {
		return sdk.Error("standard_id 必填")
	}
	activeVer := c.activeVersion(sid)
	if activeVer == "" {
		return sdk.Error("标准 " + sid + " 不存在")
	}
	raw, err := sdk.Instance.GetStateByte(prefixSM+safeKey(sid)+"_"+activeVer, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("标准 " + sid + " 当前版本记录缺失")
	}
	var cur Standard
	if e := json.Unmarshal(raw, &cur); e != nil {
		return sdk.Error("当前版本解析失败")
	}
	cur.Status = "revoked"
	cur.UpdateTime = strconv.FormatInt(c.txTs(), 10)
	b, _ := json.Marshal(cur)
	_ = sdk.Instance.PutStateByte(prefixSM+safeKey(sid)+"_"+activeVer, "", b)
	return sdk.Success(b)
}

// ---------------------------------------------------------------- 读：查询

func (c *StandardManagerContract) getStandard() protogo.Response {
	a := sdk.Instance.GetArgs()
	sid := strings.TrimSpace(string(a["standard_id"]))
	if sid == "" {
		return sdk.Error("standard_id 必填")
	}
	ver := strings.TrimSpace(string(a["version"]))
	if ver == "" {
		ver = c.activeVersion(sid)
	}
	if ver == "" {
		return sdk.Error("标准 " + sid + " 不存在")
	}
	raw, err := sdk.Instance.GetStateByte(prefixSM+safeKey(sid)+"_"+ver, "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("标准 " + sid + " 版本 " + ver + " 不存在")
	}
	return sdk.Success(raw)
}

func (c *StandardManagerContract) queryStandards() protogo.Response {
	status := strings.TrimSpace(string(sdk.Instance.GetArgs()["status"]))
	ids := c.loadIdx()
	out := make([]Standard, 0, len(ids))
	for _, sid := range ids {
		ver := c.activeVersion(sid)
		if ver == "" {
			continue
		}
		raw, err := sdk.Instance.GetStateByte(prefixSM+safeKey(sid)+"_"+ver, "")
		if err != nil || len(raw) == 0 {
			continue
		}
		var st Standard
		if json.Unmarshal(raw, &st) != nil {
			continue
		}
		if status != "" && st.Status != status {
			continue
		}
		out = append(out, st)
	}
	b, _ := json.Marshal(out)
	return sdk.Success(b)
}

// ---------------------------------------------------------------- 索引辅助

func (c *StandardManagerContract) loadIdx() []string {
	raw, err := sdk.Instance.GetStateByte(prefixSMIdx, "")
	if err != nil || len(raw) == 0 {
		return []string{}
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return []string{}
	}
	return ids
}

func (c *StandardManagerContract) appendIdx(id string) {
	ids := c.loadIdx()
	for _, x := range ids {
		if x == id {
			return // 已存在
		}
	}
	ids = append(ids, id)
	b, _ := json.Marshal(ids)
	_ = sdk.Instance.PutStateByte(prefixSMIdx, "", b)
}

func (c *StandardManagerContract) activeVersion(sid string) string {
	raw, err := sdk.Instance.GetStateByte(prefixSMActive+safeKey(sid), "")
	if err != nil || len(raw) == 0 {
		return ""
	}
	return string(raw)
}

// ---------------------------------------------------------------- 治理辅助

func (c *StandardManagerContract) isAdmin(did string) bool {
	if did == "" {
		return false
	}
	raw, err := sdk.Instance.GetStateByte(prefixAdmin+safeKey(did), "")
	return err == nil && len(raw) > 0
}

func (c *StandardManagerContract) adminQuota() int {
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

func (c *StandardManagerContract) txTs() int64 {
	ts, _ := sdk.Instance.GetTxTimeStamp()
	return parseInt(ts)
}

func main() {
	err := sandbox.Start(new(StandardManagerContract))
	if err != nil {
		sdk.Instance.Errorf("contract start failed: %v", err)
	}
}

// safeKey 将 DID 等含非法字符的标识转换为 ChainMaker 合法的 state key。
// ChainMaker 约束：DefaultStateRegex = "^[a-zA-Z0-9._-]+$"（冒号非法）。
// 做法：非法字符逐字节替换为 '_'，并追加原串 sha256 前 4 字节的 hex 短哈希，避免碰撞。
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

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
