// data_certify.go —— 任务三：畜牧产品质量认证链上合约
//
// 隐私纪律（数据不出域 / 最小够用，对齐 GB/T 43697-2024）：
//   链上**只存认证结论、指纹/承诺哈希、权属 DID、指标标签、逐字段等级标签与预警原因**，
//   绝不存原始检测值、企业敏感字段明文。原始数值仅留本地 SQLite（quality.db）。
//   链上记录是「本地裁决结论的不可篡改存证镜像」，供监管侧审计与跨方验真。
//
// 方法：
//   certifyData          认证上链（pass / fail / conditional），幂等（同 certId 不可重复）
//   CERT_ALERT           不合格预警上链（链下整改闭环留痕）
//   getCertification     按 certId 查询
//   queryCertifications  列表查询（按 data_did / result / status 过滤）
//   revokeCertification  撤销（状态置 revoked）
//
// 构建（VM）：
//   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o contract_name data_certify.go
//   7z a -t7z data_certify.7z contract_name Dockerfile
// 部署：
//   cmc client contract user create --contract-name=data_certify --version=1.0.0 \
//     --byte-code-path=.../data_certify.7z --runtime-type=DOCKER_GO --sync-result=true

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
	prefixDC       = "dc_"    // dc:<safeKey(certId)>             -> 认证记录
	prefixDCIdx    = "dc_idx" // JSON 数组：所有 certId（枚举用）
	prefixDCByData = "dcb_"   // dcb:<safeKey(dataDid)>:<certId>  -> 按数据 DID 的索引
	prefixDCAlert  = "dca_"   // dca:<safeKey(alertId)>           -> 预警记录
	prefixDCRect   = "dcr_"   // dcr:<safeKey(alertId)>_<seq>     -> 整改/复检流水（append-only）
	prefixAdmin    = "admin_"
	keyAdminQuota  = "admin_quota"
)

// Certification 认证记录（链上镜像：结论 + 指纹，无原值）
type Certification struct {
	CertId          string `json:"cert_id"`
	StandardId      string `json:"standard_id"`
	StandardVersion string `json:"standard_version"`
	DataDid         string `json:"data_did"`         // 数据 DID，非原文
	DataFingerprint string `json:"data_fingerprint"` // 指纹/承诺哈希，不可还原原始数据
	CertifierDid    string `json:"certifier_did"`    // 认证主体 DID
	Item            string `json:"item"`             // 指标标签（如「兽药残留」），非检测值
	BusinessTime    string `json:"business_time"`
	ChainTime       string `json:"chain_time"`
	Result          string `json:"result"`     // pass | fail | conditional
	Status          string `json:"status"`     // active | revoked
	Reason          string `json:"reason"`     // 不合格原因（标签，如「超过上限」）
	RiskLevel       string `json:"risk_level"` // none | low | medium | high
	Fields          string `json:"fields"`     // JSON: {字段名: L1..L4}，仅等级标签
}

// CertAlert 不合格预警记录（整改闭环留痕）
type CertAlert struct {
	AlertId    string `json:"alert_id"`
	CertId     string `json:"cert_id"`
	Item       string `json:"item"`
	ExceedType string `json:"exceed_type"`
	RiskLevel  string `json:"risk_level"`
	Status     string `json:"status"` // open | rectifying | recheck_passed | closed
	ChainTime  string `json:"chain_time"`
}

// RectifyRecord 整改/复检流水（append-only：每次整改或复检追加一条，形成整改闭环链）
type RectifyRecord struct {
	RecordId    string `json:"record_id"`    // rect_<alertId>_<seq>
	AlertId     string `json:"alert_id"`     // 关联预警
	Action      string `json:"action"`       // rectify(整改) | recheck(复检)
	Note        string `json:"note"`         // 整改说明/复检结论（短文本）
	EvidenceHash string `json:"evidence_hash"` // 整改证据哈希（链下原始证据摘要）
	Status      string `json:"status"`       // rectifying | recheck_passed | recheck_failed | closed
	SubmitterDid string `json:"submitter_did"` // 提交方 DID（企业/检测机构）
	ChainTime   string `json:"chain_time"`
}

type DataCertifyContract struct{}

// ---------------------------------------------------------------- 生命周期

func (c *DataCertifyContract) InitContract() protogo.Response {
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
	sdk.Instance.Infof("data_certify initialized, version=%s quota=%s", contractVersion, quota)
	return sdk.Success([]byte("init ok, version=" + contractVersion))
}

func (c *DataCertifyContract) UpgradeContract() protogo.Response {
	sdk.Instance.Infof("data_certify upgraded to %s", contractVersion)
	return sdk.Success([]byte("upgrade ok, version=" + contractVersion))
}

func (c *DataCertifyContract) InvokeContract(method string) protogo.Response {
	switch method {
	case "certifyData":
		return c.certifyData()
	case "CERT_ALERT":
		return c.certAlert()
	case "rectifyRecord":
		return c.rectifyRecord()
	case "getCertification":
		return c.getCertification()
	case "queryCertifications":
		return c.queryCertifications()
	case "queryRectifyRecords":
		return c.queryRectifyRecords()
	case "revokeCertification":
		return c.revokeCertification()
	case "version":
		return sdk.Success([]byte(contractVersion))
	default:
		return sdk.Error("未知方法: " + method)
	}
}

// ---------------------------------------------------------------- 写：认证 / 预警

// certifyData 认证上链。幂等：同 certId 不可重复写入（重认证须走新 certId）。
// 非 admin 门控：链上是本地裁决结论的存证镜像，任意已认证主体可记录，certifier_did 留痕。
func (c *DataCertifyContract) certifyData() protogo.Response {
	a := sdk.Instance.GetArgs()
	certId := strings.TrimSpace(string(a["cert_id"]))
	if certId == "" {
		return sdk.Error("cert_id 必填")
	}
	if raw, _ := sdk.Instance.GetStateByte(prefixDC+safeKey(certId), ""); len(raw) > 0 {
		return sdk.Error("cert_id " + certId + " 已存在，不可重复认证（重认证请使用新 certId）")
	}
	now := strconv.FormatInt(c.txTs(), 10)
	rec := Certification{
		CertId:          certId,
		StandardId:      strings.TrimSpace(string(a["standard_id"])),
		StandardVersion: strings.TrimSpace(string(a["standard_version"])),
		DataDid:         strings.TrimSpace(string(a["data_did"])),
		DataFingerprint: strings.TrimSpace(string(a["data_fingerprint"])),
		CertifierDid:    strings.TrimSpace(string(a["certifier_did"])),
		Item:            strings.TrimSpace(string(a["item"])),
		BusinessTime:    strings.TrimSpace(string(a["business_time"])),
		ChainTime:       now,
		Result:          strings.TrimSpace(string(a["result"])),
		Status:          "active",
		Reason:          strings.TrimSpace(string(a["reason"])),
		RiskLevel:       strings.TrimSpace(string(a["risk_level"])),
		Fields:          strings.TrimSpace(string(a["fields"])),
	}
	if rec.Result == "" {
		rec.Result = "conditional"
	}
	b, _ := json.Marshal(rec)
	if err := sdk.Instance.PutStateByte(prefixDC+safeKey(certId), "", b); err != nil {
		return sdk.Error("认证写入失败: " + err.Error())
	}
	c.appendIdx(certId)
	if rec.DataDid != "" {
		_ = sdk.Instance.PutStateByte(prefixDCByData+safeKey(rec.DataDid)+"_"+safeKey(certId), "", b)
	}
	return sdk.Success(b)
}

// certAlert 不合格预警上链（整改闭环留痕）
func (c *DataCertifyContract) certAlert() protogo.Response {
	a := sdk.Instance.GetArgs()
	alertId := strings.TrimSpace(string(a["alert_id"]))
	if alertId == "" {
		return sdk.Error("alert_id 必填")
	}
	now := strconv.FormatInt(c.txTs(), 10)
	al := CertAlert{
		AlertId:    alertId,
		CertId:     strings.TrimSpace(string(a["cert_id"])),
		Item:       strings.TrimSpace(string(a["item"])),
		ExceedType: strings.TrimSpace(string(a["exceed_type"])),
		RiskLevel:  strings.TrimSpace(string(a["risk_level"])),
		Status:     strings.TrimSpace(string(a["status"])),
		ChainTime:  now,
	}
	if al.Status == "" {
		al.Status = "open"
	}
	b, _ := json.Marshal(al)
	if err := sdk.Instance.PutStateByte(prefixDCAlert+safeKey(alertId), "", b); err != nil {
		return sdk.Error("预警写入失败: " + err.Error())
	}
	return sdk.Success(b)
}

// rectifyRecord 整改/复检记录上链（append-only 流水，支撑整改闭环审计）
// 入参：alert_id(必填), action(rectify|recheck), note, evidence_hash, status, submitter_did
func (c *DataCertifyContract) rectifyRecord() protogo.Response {
	a := sdk.Instance.GetArgs()
	alertId := strings.TrimSpace(string(a["alert_id"]))
	if alertId == "" {
		return sdk.Error("alert_id 必填")
	}
	action := strings.TrimSpace(string(a["action"]))
	if action == "" {
		action = "rectify"
	}
	now := strconv.FormatInt(c.txTs(), 10)
	// 关联的预警必须已存在（整改闭环只针对链上已存证的预警）
	raw, _ := sdk.Instance.GetStateByte(prefixDCAlert+safeKey(alertId), "")
	if len(raw) == 0 {
		return sdk.Error("预警 " + alertId + " 不存在，请先 CERT_ALERT 上链")
	}
	// 流水序号：dcr:<alertId>_<seq>，seq 从 1 递增
	seq := c.rectSeq(alertId) + 1
	rec := RectifyRecord{
		RecordId:     "rect_" + safeKey(alertId) + "_" + strconv.FormatInt(seq, 10),
		AlertId:      alertId,
		Action:       action,
		Note:         strings.TrimSpace(string(a["note"])),
		EvidenceHash: strings.TrimSpace(string(a["evidence_hash"])),
		Status:       strings.TrimSpace(string(a["status"])),
		SubmitterDid: strings.TrimSpace(string(a["submitter_did"])),
		ChainTime:    now,
	}
	b, _ := json.Marshal(rec)
	if err := sdk.Instance.PutStateByte(
		prefixDCRect+safeKey(alertId)+"_"+strconv.FormatInt(seq, 10), "", b); err != nil {
		return sdk.Error("整改记录写入失败: " + err.Error())
	}
	// 同步更新预警主记录状态（open -> rectifying -> recheck_passed/closed）
	var al CertAlert
	if e := json.Unmarshal(raw, &al); e == nil && rec.Status != "" {
		al.Status = rec.Status
		al.ChainTime = now
		ab, _ := json.Marshal(al)
		_ = sdk.Instance.PutStateByte(prefixDCAlert+safeKey(alertId), "", ab)
	}
	return sdk.Success(b)
}

// queryRectifyRecords 按预警查询整改/复检流水
// 入参：alert_id(必填), limit(可选，默认 50)
func (c *DataCertifyContract) queryRectifyRecords() protogo.Response {
	a := sdk.Instance.GetArgs()
	alertId := strings.TrimSpace(string(a["alert_id"]))
	if alertId == "" {
		return sdk.Error("alert_id 必填")
	}
	limit := parseInt(string(a["limit"]))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := make([]RectifyRecord, 0, limit)
	for seq := c.rectSeq(alertId); seq > 0 && int64(len(out)) < limit; seq-- {
		raw, err := sdk.Instance.GetStateByte(
			prefixDCRect+safeKey(alertId)+"_"+strconv.FormatInt(seq, 10), "")
		if err != nil || len(raw) == 0 {
			continue
		}
		var rec RectifyRecord
		if json.Unmarshal(raw, &rec) == nil {
			out = append(out, rec)
		}
	}
	b, _ := json.Marshal(out)
	return sdk.Success(b)
}

// revokeCertification 撤销认证（状态置 revoked，链上不可篡改但可标记失效）
func (c *DataCertifyContract) revokeCertification() protogo.Response {
	a := sdk.Instance.GetArgs()
	certId := strings.TrimSpace(string(a["cert_id"]))
	if certId == "" {
		return sdk.Error("cert_id 必填")
	}
	raw, err := sdk.Instance.GetStateByte(prefixDC+safeKey(certId), "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("认证 " + certId + " 不存在")
	}
	var rec Certification
	if e := json.Unmarshal(raw, &rec); e != nil {
		return sdk.Error("认证记录解析失败")
	}
	rec.Status = "revoked"
	b, _ := json.Marshal(rec)
	_ = sdk.Instance.PutStateByte(prefixDC+safeKey(certId), "", b)
	if rec.DataDid != "" {
		_ = sdk.Instance.PutStateByte(prefixDCByData+safeKey(rec.DataDid)+"_"+safeKey(certId), "", b)
	}
	return sdk.Success(b)
}

// ---------------------------------------------------------------- 读：查询

func (c *DataCertifyContract) getCertification() protogo.Response {
	a := sdk.Instance.GetArgs()
	certId := strings.TrimSpace(string(a["cert_id"]))
	if certId == "" {
		return sdk.Error("cert_id 必填")
	}
	raw, err := sdk.Instance.GetStateByte(prefixDC+safeKey(certId), "")
	if err != nil || len(raw) == 0 {
		return sdk.Error("认证 " + certId + " 不存在")
	}
	return sdk.Success(raw)
}

func (c *DataCertifyContract) queryCertifications() protogo.Response {
	a := sdk.Instance.GetArgs()
	fDataDid := strings.TrimSpace(string(a["data_did"]))
	fResult := strings.TrimSpace(string(a["result"]))
	fStatus := strings.TrimSpace(string(a["status"]))
	ids := c.loadIdx()
	out := make([]Certification, 0, len(ids))
	for _, cid := range ids {
		raw, err := sdk.Instance.GetStateByte(prefixDC+safeKey(cid), "")
		if err != nil || len(raw) == 0 {
			continue
		}
		var rec Certification
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		if fDataDid != "" && rec.DataDid != fDataDid {
			continue
		}
		if fResult != "" && rec.Result != fResult {
			continue
		}
		if fStatus != "" && rec.Status != fStatus {
			continue
		}
		out = append(out, rec)
	}
	b, _ := json.Marshal(out)
	return sdk.Success(b)
}

// ---------------------------------------------------------------- 索引辅助

func (c *DataCertifyContract) loadIdx() []string {
	raw, err := sdk.Instance.GetStateByte(prefixDCIdx, "")
	if err != nil || len(raw) == 0 {
		return []string{}
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return []string{}
	}
	return ids
}

func (c *DataCertifyContract) appendIdx(id string) {
	ids := c.loadIdx()
	for _, x := range ids {
		if x == id {
			return
		}
	}
	ids = append(ids, id)
	b, _ := json.Marshal(ids)
	_ = sdk.Instance.PutStateByte(prefixDCIdx, "", b)
}

// ---------------------------------------------------------------- 治理辅助

func (c *DataCertifyContract) isAdmin(did string) bool {
	if did == "" {
		return false
	}
	raw, err := sdk.Instance.GetStateByte(prefixAdmin+safeKey(did), "")
	return err == nil && len(raw) > 0
}

func (c *DataCertifyContract) adminQuota() int {
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

func (c *DataCertifyContract) txTs() int64 {
	ts, _ := sdk.Instance.GetTxTimeStamp()
	return parseInt(ts)
}

// rectSeq 返回某预警的整改流水当前最大序号（0 = 尚无流水）
func (c *DataCertifyContract) rectSeq(alertId string) int64 {
	seq := int64(0)
	for i := int64(1); i < 1<<30; i++ {
		raw, err := sdk.Instance.GetStateByte(
			prefixDCRect+safeKey(alertId)+"_"+strconv.FormatInt(i, 10), "")
		if err != nil || len(raw) == 0 {
			break
		}
		seq = i
	}
	return seq
}

func main() {
	err := sandbox.Start(new(DataCertifyContract))
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
