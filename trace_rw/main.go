package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"sort"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

// trace_rw 合约：读写依赖边的链上持久存证与可验证查询（任务四·M3 合约化）
//
// 对应实施方案（3-5-23）第 3 点："通过分析读写集并捕获其读写依赖，并经由合约将
// 其持久存证，从而可支持后续的溯源查询。"
//
// 设计（边级可验证，而非仅摘要上链）：
//   - saveDeps(deps)        批量存入依赖边（写者tx@height →key→ 读者tx@height）
//   - getDepsByReader(tx)   这笔交易读了哪些状态、由哪些前序交易产生（后向因果）
//   - getDepsByWriter(tx)   这笔交易写的状态被哪些后续交易消费（前向因果）
//   - verifyDep(reader, key) 单条边的存在性验证（配合 depsRoot 聚合根）
//   - depsRoot()            全部边的确定性聚合根（排序滚动哈希），锚定可复核
//
// 存储 Key：
//   DEP_<readerTx>#<key>    边 JSON（幂等：同 (reader,key) 覆盖为最新）
//   RWI_R_<readerTx>        该读者的边键列表
//   RWI_W_<writerTx>        该写者的边键列表
//   DEP_KEYS                全量边键（聚合根用；量级受 span 限制）
//   DEP_ROOT                当前聚合根 {root, count, updated_at}
//
// 隐私纪律：边只含交易哈希、高度、**状态键名**（键名非数据值）、合约名——
// 不含任何字段值与原文。

type Dep struct {
	DepTx        string `json:"dep_tx"`
	DepHeight    int64  `json:"dep_height"`
	ReaderTx     string `json:"reader_tx"`
	ReaderHeight int64  `json:"reader_height"`
	Key          string `json:"key"`
	Contract     string `json:"contract"`
}

type TraceRwContract struct{}

func (c *TraceRwContract) InitContract() protogo.Response {
	return sdk.Success([]byte("trace_rw initialized"))
}

func (c *TraceRwContract) UpgradeContract() protogo.Response {
	return sdk.Success([]byte("trace_rw upgraded"))
}

func (c *TraceRwContract) InvokeContract(method string) protogo.Response {
	switch method {
	case "saveDeps":
		return c.saveDeps()
	case "getDepsByReader":
		return c.getDepsByReader()
	case "getDepsByWriter":
		return c.getDepsByWriter()
	case "verifyDep":
		return c.verifyDep()
	case "depsRoot":
		return c.depsRoot()
	default:
		return sdk.Error("unknown method: " + method)
	}
}

func h(s string) string {
	hh := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hh[:])
}

func depKey(d Dep) string {
	return "DEP_" + h(d.ReaderTx + "#" + d.Key)
}

func readIDs(key string) []string {
	raw, err := sdk.Instance.GetStateByte(key, "ids")
	if err != nil || raw == nil {
		return []string{}
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return []string{}
	}
	return ids
}

func writeIDs(key string, ids []string) error {
	js, _ := json.Marshal(ids)
	return sdk.Instance.PutStateByte(key, "ids", js)
}

func addToIndex(indexKey, val string) {
	ids := readIDs(indexKey)
	for _, v := range ids {
		if v == val {
			return
		}
	}
	ids = append(ids, val)
	_ = writeIDs(indexKey, ids)
}

// rollingRoot 对排序后的边键做确定性滚动哈希
func rollingRoot(sortedKeys []string) string {
	h := sha256.Sum256([]byte(""))
	cur := h[:]
	for _, k := range sortedKeys {
		n := sha256.Sum256(append(cur, []byte(k)...))
		cur = n[:]
	}
	return hex.EncodeToString(cur)
}

// saveDeps 批量存依赖边。入参 deps = JSON 数组字符串。
// 返回 {saved, total, root}
func (c *TraceRwContract) saveDeps() protogo.Response {
	args := sdk.Instance.GetArgs()
	raw := string(args["deps"])
	if raw == "" {
		return sdk.Error("deps is required")
	}
	var deps []Dep
	if err := json.Unmarshal([]byte(raw), &deps); err != nil {
		return sdk.Error("deps is invalid json: " + err.Error())
	}
	if len(deps) == 0 {
		return sdk.Error("deps is empty")
	}
	if len(deps) > 500 {
		deps = deps[:500] // 单笔交易上限，防爆块
	}

	saved := 0
	for _, d := range deps {
		if d.ReaderTx == "" || d.Key == "" || d.DepTx == "" {
			continue
		}
		dj, _ := json.Marshal(d)
		k := depKey(d)
		if err := sdk.Instance.PutStateByte(k, "dep", dj); err != nil {
			return sdk.Error("put dep error: " + err.Error())
		}
		addToIndex("RWI_R_"+h(d.ReaderTx), k)
		addToIndex("RWI_W_"+h(d.DepTx), k)
		addToIndex("DEP_KEYS", k)
		saved++
	}

	all := readIDs("DEP_KEYS")
	sort.Strings(all)
	root := rollingRoot(all)
	meta, _ := json.Marshal(map[string]interface{}{
		"root": root, "count": len(all),
		"updated_at": time.Now().Unix(),
	})
	_ = sdk.Instance.PutStateByte("DEP_ROOT", "v", meta)

	out, _ := json.Marshal(map[string]interface{}{
		"saved": saved, "total": len(all), "root": root,
	})
	sdk.Instance.EmitEvent("DEPS_SAVED", []string{fmt.Sprintf("%d", saved), root})
	return sdk.Success(out)
}

func (c *TraceRwContract) loadDeps(indexKey string) protogo.Response {
	keys := readIDs(indexKey)
	deps := make([]Dep, 0, len(keys))
	for _, k := range keys {
		raw, err := sdk.Instance.GetStateByte(k, "dep")
		if err != nil || raw == nil {
			continue
		}
		var d Dep
		if json.Unmarshal(raw, &d) == nil {
			deps = append(deps, d)
		}
	}
	js, _ := json.Marshal(deps)
	return sdk.Success(js)
}

// getDepsByReader 这笔交易读了哪些状态（后向因果：值由谁产生）
func (c *TraceRwContract) getDepsByReader() protogo.Response {
	tx := string(sdk.Instance.GetArgs()["reader_tx"])
	if tx == "" {
		return sdk.Error("reader_tx is required")
	}
	return c.loadDeps("RWI_R_" + h(tx))
}

// getDepsByWriter 这笔交易写的状态被谁消费（前向因果）
func (c *TraceRwContract) getDepsByWriter() protogo.Response {
	tx := string(sdk.Instance.GetArgs()["dep_tx"])
	if tx == "" {
		return sdk.Error("dep_tx is required")
	}
	return c.loadDeps("RWI_W_" + h(tx))
}

// verifyDep 单条边存在性验证：返回 {exists, dep, root}
func (c *TraceRwContract) verifyDep() protogo.Response {
	args := sdk.Instance.GetArgs()
	tx := string(args["reader_tx"])
	key := string(args["key"])
	if tx == "" || key == "" {
		return sdk.Error("reader_tx and key are required")
	}
	out := map[string]interface{}{"exists": false}
	raw, err := sdk.Instance.GetStateByte("DEP_"+h(tx+"#"+key), "dep")
	if err == nil && raw != nil {
		var d Dep
		if json.Unmarshal(raw, &d) == nil {
			out["exists"] = true
			out["dep"] = d
		}
	}
	if rr, _ := sdk.Instance.GetStateByte("DEP_ROOT", "v"); rr != nil {
		var m map[string]interface{}
		if json.Unmarshal(rr, &m) == nil {
			out["root"] = m["root"]
			out["count"] = m["count"]
		}
	}
	js, _ := json.Marshal(out)
	return sdk.Success(js)
}

// depsRoot 返回聚合根与边总数
func (c *TraceRwContract) depsRoot() protogo.Response {
	rr, _ := sdk.Instance.GetStateByte("DEP_ROOT", "v")
	if rr == nil {
		return sdk.Success([]byte(`{"root":"","count":0}`))
	}
	return sdk.Success(rr)
}

func main() {
	if err := sandbox.Start(new(TraceRwContract)); err != nil {
		log.Fatal(err)
	}
}
