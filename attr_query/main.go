package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

// attr_query 合约：多属性哈希实体匹配查询（任务四·步骤①）
//
// 解决的问题：基于多维属性匹配真实企业数据时，传统数据库的多属性联合查询（逐属性
// AND/OR 扫描）效率低下。多属性哈希（Multi-Attribute Hashing）通过设计专门的属性
// 特征化 + 哈希分桶策略：
//   - 把企业多维属性转化为一组"带类型前缀的属性 token"：属性值相同 → 相同 token；
//     属性值相似（名称共享字符、产品共享词、地区同省）→ 共享 token；
//   - token 经确定性哈希落入桶（BUCKET_{hash}），共享 token 的实体被组织进同一桶
//     （相近桶 = 共享属性 token 的桶集合），从而在多维空间中捕捉数据的复杂特性；
//   - 查询时对"特定属性组合"做同样特征化 + 哈希，只读取命中桶即可得到候选集；
//     并借鉴 LSH multi-probing，对产品词的前缀相近桶做多探针探测提升召回，
//     无需扫描全量数据，实现高效实体匹配。
//
// 存储 Key 规则（[key, field] 模型）：
//   key = GLOBAL_ENT_SEQ,  field = seq  实体自增 id 计数器
//   key = ENT_{id},        field = data 企业实体记录（含 TokenCount）
//   key = UCC_{uscc},      field = id   统一社会信用代码精确索引（金钥）
//   key = BUCKET_{hash64}, field = ids  多属性哈希桶（存实体 id 列表）
//   key = ENT_ALL,         field = ids  全量实体 id 列表（分页/演示）

const (
	maxBucketIDs    = 2000 // 单桶最大容量（防桶无限膨胀）
	maxEvaluate     = 400  // 单次查询最多评估候选数（控制链上执行量）
	maxQueryTokens  = 64   // 单次查询属性 token 上限
	maxProbeDepth   = 2    // 多探针：产品词前缀截断深度（相近桶探测）
	probeWeight     = 0.5  // 多探针：相近桶命中的权重（低于精确命中）
	weightCoverage  = 0.4  // 综合得分权重：查询属性组合覆盖率
	weightJaccard   = 0.3  // 综合得分权重：整体属性 Jaccard 相似度
	weightAttrScore = 0.2  // 综合得分权重：属性组合精确匹配率
	weightFuzzy     = 0.1  // 综合得分权重：多探针相近命中贡献（模糊覆盖率）
)

type AttrQueryContract struct{}

// Entity 企业实体（真实企业多维属性）
type Entity struct {
	Id         string `json:"id"`
	Name       string `json:"name"`       // 企业名称
	Uscc       string `json:"uscc"`       // 统一社会信用代码（精确金钥）
	Region     string `json:"region"`     // 地区（省 / 省+市）
	BizType    string `json:"bizType"`    // 经营类型
	Products   string `json:"products"`   // 主营产品（逗号分隔）
	Grade      string `json:"grade"`      // 质量等级
	Scale      string `json:"scale"`      // 规模
	Status     string `json:"status"`     // 经营状态
	TokenCount int    `json:"tokenCount"` // 该实体保存时的属性 token 数
}

// MatchItem 单个匹配结果
type MatchItem struct {
	Id            string  `json:"id"`
	Name          string  `json:"name"`
	Uscc          string  `json:"uscc"`
	Region        string  `json:"region"`
	BizType       string  `json:"bizType"`
	Products      string  `json:"products"`
	Grade         string  `json:"grade"`
	Scale         string  `json:"scale"`
	Status        string  `json:"status"`
	HitCount      int     `json:"hitCount"`      // 精确命中的查询属性 token 数
	ProbeHit      int     `json:"probeHit"`      // 多探针命中的相近 token 数（前缀相近产品词）
	TokenCount    int     `json:"tokenCount"`    // 候选自身属性 token 数
	Coverage      float64 `json:"coverage"`      // 查询组合覆盖率 = 精确命中token/查询token
	FuzzyCoverage float64 `json:"fuzzyCoverage"` // 含多探针覆盖率 = (精确+0.5*探针)/查询token
	Jaccard       float64 `json:"jaccard"`       // 属性 token 集合 Jaccard 相似度
	AttrScore     float64 `json:"attrScore"`     // 属性组合精确匹配率
	Score         float64 `json:"score"`         // 综合得分 0-100
}

// MatchResult 查询返回体
type MatchResult struct {
	Query       string      `json:"query"`       // 查询属性组合
	QueryTokens int         `json:"queryTokens"` // 查询产生的属性 token 数
	Candidates  int         `json:"candidates"`  // 哈希取桶得到的候选数
	TopK        int         `json:"topK"`
	Matches     []MatchItem `json:"matches"`
}

func (c *AttrQueryContract) InitContract() protogo.Response {
	return sdk.Success([]byte("attr_query initialized"))
}

func (c *AttrQueryContract) UpgradeContract() protogo.Response {
	return sdk.Success([]byte("attr_query upgraded"))
}

func (c *AttrQueryContract) InvokeContract(method string) protogo.Response {
	switch method {
	case "saveEntity":
		return c.saveEntity()
	case "matchEntity":
		return c.matchEntity()
	case "getEntity":
		return c.getEntity()
	case "getBucketByToken":
		return c.getBucketByToken()
	case "queryAllEntitiesPage":
		return c.queryAllEntitiesPage()
	default:
		return sdk.Error(fmt.Sprintf("unknown method: %s", method))
	}
}

// ============================== 写操作（合约调用） ==============================

// saveEntity 保存企业实体，并按多属性哈希建立桶索引
// 入参：data = 企业属性 JSON（name 必填，其余可选）
func (c *AttrQueryContract) saveEntity() protogo.Response {
	args := sdk.Instance.GetArgs()
	data := string(args["data"])
	if data == "" {
		return sdk.Error("data is required")
	}

	var e Entity
	if err := json.Unmarshal([]byte(data), &e); err != nil {
		return sdk.Error("data is invalid json: " + err.Error())
	}
	if e.Name == "" {
		return sdk.Error("name is required")
	}

	// 自增实体 id
	seq, _ := sdk.Instance.GetStateByte("GLOBAL_ENT_SEQ", "seq")
	next := int64(1)
	if seq != nil {
		if v, err := strconv.ParseInt(string(seq), 10, 64); err == nil {
			next = v + 1
		}
	}
	id := "E" + strconv.FormatInt(next, 10)
	e.Id = id

	tokens := tokensOf(&e)
	e.TokenCount = len(tokens)

	entJson, _ := json.Marshal(e)
	if err := sdk.Instance.PutStateByte("ENT_"+id, "data", entJson); err != nil {
		return sdk.Error("put entity error: " + err.Error())
	}

	// 信用代码精确索引
	if e.Uscc != "" {
		if err := sdk.Instance.PutStateByte("UCC_"+e.Uscc, "id", []byte(id)); err != nil {
			return sdk.Error("put ucc index error: " + err.Error())
		}
	}

	// 多属性哈希分桶：每个属性 token 落到一个桶，共享 token 的实体进同一桶；
	// 多探针：产品词的"前缀相近 token"也注册进桶（如 p=生猪养殖 同时挂到 p=生猪），
	//         使相近桶里真正装进相近属性的实体，查询时前缀探针才能召回。
	for _, tok := range tokens {
		c.registerToBucket(id, tok)
		for _, nt := range neighborTokens(tok, maxProbeDepth) {
			c.registerToBucket(id, nt)
		}
	}

	// 全量 id 列表（避免迭代器，沿用 INDEX + GetStateByte 模式）
	all := readIDs("ENT_ALL")
	all = append(all, id)
	_ = writeIDs("ENT_ALL", all)

	// 计数器
	_ = sdk.Instance.PutStateByte("GLOBAL_ENT_SEQ", "seq", []byte(strconv.FormatInt(next, 10)))

	sdk.Instance.EmitEvent("ENTITY_SAVED", []string{id, e.Name, strconv.Itoa(e.TokenCount)})

	return sdk.Success(entJson)
}

// ============================== 读操作（合约查询） ==============================

// matchEntity 多属性哈希实体匹配查询（核心，含多探针）
// 入参：query = 属性组合 JSON（任意子集，未提供属性留空）, k = 返回前几名（默认5，最大20）
// 流程：属性组合 → 特征化 → 精确取桶 → 多探针相近桶 → 候选集(exact/probe) → 打分排序 → topK
func (c *AttrQueryContract) matchEntity() protogo.Response {
	args := sdk.Instance.GetArgs()
	qj := string(args["query"])
	if qj == "" {
		return sdk.Error("query is required")
	}
	k, _ := strconv.Atoi(string(args["k"]))
	if k <= 0 {
		k = 5
	}
	if k > 20 {
		k = 20
	}

	var q Entity
	if err := json.Unmarshal([]byte(qj), &q); err != nil {
		return sdk.Error("query is invalid json: " + err.Error())
	}

	// 精确金钥：提供信用代码 → 直接命中，跳过哈希检索
	if q.Uscc != "" {
		if idb, _ := sdk.Instance.GetStateByte("UCC_"+q.Uscc, "id"); idb != nil {
			e := c.loadEntity(string(idb))
			if e != nil {
				res := MatchResult{
					Query: qj, QueryTokens: 1, Candidates: 1, TopK: k,
					Matches: []MatchItem{{
						Id: e.Id, Name: e.Name, Uscc: e.Uscc, Region: e.Region,
						BizType: e.BizType, Products: e.Products, Grade: e.Grade,
						Scale: e.Scale, Status: e.Status,
						HitCount: e.TokenCount, TokenCount: e.TokenCount,
						Coverage: 1, FuzzyCoverage: 1, Jaccard: 1, AttrScore: 1, Score: 100,
					}},
				}
				js, _ := json.Marshal(res)
				return sdk.Success(js)
			}
		}
	}

	tokens := tokensOf(&q)
	if len(tokens) == 0 {
		return sdk.Error("query has no attribute tokens, provide at least one attribute")
	}
	if len(tokens) > maxQueryTokens {
		tokens = tokens[:maxQueryTokens]
	}

	// 哈希取桶（多探针）：
	//   阶段1 精确桶 —— 每个查询 token 读一次桶，命中计 exact；
	//   阶段2 相近桶 —— 对产品词 token 的前缀相近 token 再探测（借鉴 LSH multi-probing），
	//          命中计 probe，权重低于精确命中；已读过的桶跳过，避免重复计数。
	type candStat struct {
		exact int
		probe int
	}
	stats := make(map[string]*candStat)
	readKeys := make(map[string]bool)

	for _, tok := range tokens {
		key := bucketKey(tok)
		readKeys[key] = true
		for _, id := range readIDs(key) {
			if stats[id] == nil {
				stats[id] = &candStat{}
			}
			stats[id].exact++
		}
	}
	for _, tok := range tokens {
		for _, nt := range neighborTokens(tok, maxProbeDepth) {
			nk := bucketKey(nt)
			if readKeys[nk] {
				continue
			}
			readKeys[nk] = true
			for _, id := range readIDs(nk) {
				if stats[id] == nil {
					stats[id] = &candStat{}
				}
				stats[id].probe++
			}
		}
	}
	if len(stats) == 0 {
		res := MatchResult{Query: qj, QueryTokens: len(tokens), Candidates: 0, TopK: k}
		js, _ := json.Marshal(res)
		return sdk.Success(js)
	}

	// 候选数上限：优先级 = 2*精确命中 + 探针命中，高者优先评估（控制链上执行量）
	cands := make([]string, 0, len(stats))
	for id := range stats {
		cands = append(cands, id)
	}
	if len(cands) > maxEvaluate {
		sort.Slice(cands, func(i, j int) bool {
			pi := stats[cands[i]].exact*2 + stats[cands[i]].probe
			pj := stats[cands[j]].exact*2 + stats[cands[j]].probe
			if pi != pj {
				return pi > pj
			}
			return cands[i] < cands[j]
		})
		cands = cands[:maxEvaluate]
	}

	provided := countProvided(&q)
	matches := make([]MatchItem, 0, len(cands))
	for _, id := range cands {
		e := c.loadEntity(id)
		if e == nil {
			continue
		}
		s := stats[id]
		h := s.exact
		ph := s.probe
		qLen := len(tokens)

		cov := math.Min(1, float64(h)/float64(qLen))
		fcov := math.Min(1, (float64(h)+probeWeight*float64(ph))/float64(qLen))
		denom := qLen + e.TokenCount - h
		if denom <= 0 {
			denom = 1
		}
		jac := math.Min(1, float64(h)/float64(denom))
		asc := math.Min(1, c.attrScore(&q, e, provided))

		score := (weightCoverage*cov + weightJaccard*jac + weightAttrScore*asc + weightFuzzy*fcov) * 100

		matches = append(matches, MatchItem{
			Id: e.Id, Name: e.Name, Uscc: e.Uscc, Region: e.Region,
			BizType: e.BizType, Products: e.Products, Grade: e.Grade,
			Scale: e.Scale, Status: e.Status,
			HitCount: h, ProbeHit: ph, TokenCount: e.TokenCount,
			Coverage: r2(cov), FuzzyCoverage: r2(fcov), Jaccard: r2(jac), AttrScore: r2(asc), Score: r2(score),
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		if matches[i].HitCount != matches[j].HitCount {
			return matches[i].HitCount > matches[j].HitCount
		}
		return matches[i].Id < matches[j].Id
	})
	if len(matches) > k {
		matches = matches[:k]
	}

	res := MatchResult{Query: qj, QueryTokens: len(tokens), Candidates: len(stats), TopK: k, Matches: matches}
	resJson, _ := json.Marshal(res)

	topId := ""
	if len(matches) > 0 {
		topId = matches[0].Id
	}
	sdk.Instance.EmitEvent("ENTITY_MATCH", []string{qj, topId, strconv.Itoa(len(matches))})

	return sdk.Success(resJson)
}

// getEntity 按实体 id 查询（不存在返回空 Payload）
// 入参：id
func (c *AttrQueryContract) getEntity() protogo.Response {
	args := sdk.Instance.GetArgs()
	id := string(args["id"])
	if id == "" {
		return sdk.Error("id is required")
	}
	raw, err := sdk.Instance.GetStateByte("ENT_"+id, "data")
	if err != nil {
		return sdk.Error("get state error: " + err.Error())
	}
	if raw == nil {
		return sdk.Success([]byte{})
	}
	return sdk.Success(raw)
}

// getBucketByToken 调试：查看某属性 token 对应桶里的实体 id 列表
// 入参：token（例如 p=生猪养殖）
func (c *AttrQueryContract) getBucketByToken() protogo.Response {
	args := sdk.Instance.GetArgs()
	token := string(args["token"])
	if token == "" {
		return sdk.Error("token is required")
	}
	ids := readIDs(bucketKey(token))
	if len(ids) == 0 {
		return sdk.Success([]byte("[]"))
	}
	js, _ := json.Marshal(ids)
	return sdk.Success(js)
}

// queryAllEntitiesPage 全量实体分页（演示/核对用）
// 入参：page（从0开始）, pageSize（默认10，最大100）
func (c *AttrQueryContract) queryAllEntitiesPage() protogo.Response {
	args := sdk.Instance.GetArgs()
	page, _ := strconv.Atoi(string(args["page"]))
	pageSize, _ := strconv.Atoi(string(args["pageSize"]))
	if page < 0 {
		page = 0
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}

	ids := readIDs("ENT_ALL")
	total := len(ids)
	start := page * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	ents := make([]json.RawMessage, 0, end-start)
	for _, id := range ids[start:end] {
		if raw, err := sdk.Instance.GetStateByte("ENT_"+id, "data"); err == nil && raw != nil {
			ents = append(ents, raw)
		}
	}

	result := struct {
		Total    int               `json:"total"`
		Page     int               `json:"page"`
		PageSize int               `json:"pageSize"`
		Entities []json.RawMessage `json:"entities"`
	}{Total: total, Page: page, PageSize: pageSize, Entities: ents}

	js, _ := json.Marshal(result)
	return sdk.Success(js)
}

// ============================== 内部工具 ==============================

// tokensOf 把实体的多维属性特征化为一组"带类型前缀的属性 token"。
// 同一 token = 属性值相同或共享字符/词 → 相似属性数据落入同一/相近桶。
func tokensOf(e *Entity) []string {
	toks := make([]string, 0, 16)
	seen := make(map[string]bool, 16)
	add := func(t string) {
		// 去重：两字名称的全名 token 与二元组相同、单级地区会与省前缀相同
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		toks = append(toks, t)
	}

	add("u=" + e.Uscc)                         // 信用代码：精确
	add("t=" + e.BizType)                      // 经营类型
	add("g=" + e.Grade)                        // 质量等级
	add("s=" + e.Scale)                        // 规模
	add("st=" + e.Status)                      // 经营状态
	for _, p := range regionLevels(e.Region) { // 地区：省 / 省+市 两级
		add("r=" + p)
	}
	if e.Name != "" { // 名称：全名 + 字符二元组（捕捉近似/模糊匹配）
		add("n=" + e.Name)
		rs := []rune(e.Name)
		for i := 0; i+1 < len(rs); i++ {
			add("n=" + string(rs[i:i+2]))
		}
	}
	for _, w := range splitWords(e.Products) { // 主营产品：词级
		add("p=" + w)
	}
	return toks
}

// regionLevels 地区层级化："河南省南阳市" → ["河南省南阳市", "河南省"]
func regionLevels(r string) []string {
	if r == "" {
		return nil
	}
	rs := []rune(r)
	res := []string{r}
	for i, c := range rs {
		switch c {
		case '省', '市', '县', '区', '州', '盟':
			res = append(res, string(rs[:i+1]))
			return res
		}
	}
	return res
}

// splitWords 主营产品分词：按中英文逗号、顿号、分号、斜杠、空白切分，去空去重
func splitWords(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ',' || c == '，' || c == '、' || c == ';' || c == '；' ||
			c == '/' || c == ' ' || c == '\t'
	})
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// neighborTokens 生成 token 的"相近 token"（多探针用）。
// 规则（词汇无关、确定性）：对主营产品词（p=）做前缀截断——去掉末尾 1..depth 个字，
// 得到更短的相近 token（如 p=肉制品加工 → p=肉制品加、p=肉制品），查询时探测其桶；
// 其余类型（u/t/g/s/st/r、名称二元组）不生成，保持精确。
func neighborTokens(tok string, depth int) []string {
	if depth <= 0 {
		return nil
	}
	i := strings.IndexByte(tok, '=')
	if i <= 0 {
		return nil
	}
	kind := tok[:i]
	if kind != "p" { // 仅主营产品词做前缀相近桶探测
		return nil
	}
	rs := []rune(tok[i+1:])
	if len(rs) < 3 {
		return nil
	}
	maxDrop := depth
	if maxDrop > len(rs)-2 {
		maxDrop = len(rs) - 2 // 至少保留 2 个字，避免噪声
	}
	out := make([]string, 0, maxDrop)
	for d := 1; d <= maxDrop; d++ {
		out = append(out, kind+"="+string(rs[:len(rs)-d]))
	}
	return out
}

// bucketKey token → 桶存储 key（FNV-1a 64 确定性哈希，保存与查询一致）
func bucketKey(token string) string {
	h := fnv.New64a()
	h.Write([]byte(token))
	return "BUCKET_" + hex.EncodeToString(h.Sum(nil))
}

// readIDs 读取 id 列表（桶 / 全量索引），无数据返回空切片
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

// writeIDs 写 id 列表
func writeIDs(key string, ids []string) error {
	js, _ := json.Marshal(ids)
	return sdk.Instance.PutStateByte(key, "ids", js)
}

// registerToBucket 把实体 id 追加进 token 对应桶（去重 + 容量上限）
func (c *AttrQueryContract) registerToBucket(id, token string) {
	key := bucketKey(token)
	ids := readIDs(key)
	for _, v := range ids {
		if v == id {
			return
		}
	}
	if len(ids) >= maxBucketIDs {
		return
	}
	ids = append(ids, id)
	_ = writeIDs(key, ids)
}

// loadEntity 载入实体记录，不存在返回 nil
func (c *AttrQueryContract) loadEntity(id string) *Entity {
	raw, err := sdk.Instance.GetStateByte("ENT_"+id, "data")
	if err != nil || raw == nil {
		return nil
	}
	var e Entity
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil
	}
	return &e
}

// countProvided 查询提供的属性数（用于精确匹配率分母）
func countProvided(q *Entity) int {
	n := 0
	if q.Region != "" {
		n++
	}
	if q.BizType != "" {
		n++
	}
	if q.Products != "" {
		n++
	}
	if q.Grade != "" {
		n++
	}
	if q.Scale != "" {
		n++
	}
	if q.Status != "" {
		n++
	}
	return n
}

// attrScore 属性组合精确匹配率：查询提供的属性里，候选精确/前缀命中几个
func (c *AttrQueryContract) attrScore(q, e *Entity, provided int) float64 {
	if provided == 0 {
		return 0
	}
	match := 0
	if q.Region != "" && (e.Region == q.Region || strings.HasPrefix(e.Region, q.Region)) {
		match++
	}
	if q.BizType != "" && e.BizType == q.BizType {
		match++
	}
	if q.Products != "" && wordsOverlap(q.Products, e.Products) {
		match++
	}
	if q.Grade != "" && e.Grade == q.Grade {
		match++
	}
	if q.Scale != "" && e.Scale == q.Scale {
		match++
	}
	if q.Status != "" && e.Status == q.Status {
		match++
	}
	return float64(match) / float64(provided)
}

// wordsOverlap 两个产品串是否存在共享词或前缀相近词（≥2 字符公共前缀，
// 与多探针语义一致，如 "生猪"↔"生猪养殖"、"肉制品"↔"肉制品加工"）
func wordsOverlap(a, b string) bool {
	sa := splitWords(a)
	if len(sa) == 0 {
		return false
	}
	sb := splitWords(b)
	for _, wa := range sa {
		for _, wb := range sb {
			if wa == wb || prefixLen(wa, wb) >= 2 {
				return true
			}
		}
	}
	return false
}

// prefixLen 两词公共前缀长度（按字符计）
func prefixLen(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	n := len(ra)
	if len(rb) < n {
		n = len(rb)
	}
	i := 0
	for i < n && ra[i] == rb[i] {
		i++
	}
	return i
}

// r2 保留两位小数
func r2(x float64) float64 {
	return math.Round(x*100) / 100
}

func main() {
	if err := sandbox.Start(new(AttrQueryContract)); err != nil {
		log.Fatal(err)
	}
}
