package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

// 현지화 보존 판정(artex-ko): 이 파일의 중국어 문자열은 전부 에이전트(두뇌) 입력이고
// HTTP 사용자 응답으로 나가지 않는다. BRIEF 경계 #1(두뇌는 번역하지 않는다 — 성능
// 보존)에 따라 원문을 그대로 둔다. 이 파일에 writeErr 는 0 — 사용자 노출 경로가 없다.
// 싱크는 세 갈래다(행 번호 대신 심볼로 가리킨다. 편집으로 밀려도 유효하게).
//
//	(1) 도구 설명·스키마 description: report_finding 의 evidence_hint_id·hints.text,
//	    bind_finding_traffic 의 wrTool 설명·finding_id strParam. LLM 이 읽는 도구
//	    정의라 두뇌 입력이다.
//	(2) 마이그레이션 매칭 문자열: seedFindingWorkflowTools 의 legacy 변수(옛 traffic_search
//	    설명)는 traffic.TrafficSearchDescription(그 자체도 중국어 도구 설명)으로 올리는
//	    UPDATE … WHERE description=$2 의 비교값이다. 번역하면 기존 행과 매칭되지 않아
//	    업그레이드가 멈춘다.
//	(3) actool.Errorf 도구 결과: agentFindingTrafficAccess 의 오류들은 유일 호출처
//	    toolBindFindingTraffic(이 파일)과 get_finding_traffic(finding_traffic.go) 두
//	    도구에서 모두 actool.Errorf(err.Error()) 로 감싸 에이전트에게 되돌아가고,
//	    toolBindFindingTraffic 의 바인딩 비활성·빈 traffic_refs 문구는 직접 actool.Errorf 다.
//
// 다음 기여자가 "마저 번역"하다 벤치마크된 두뇌 입력을 바꾸지 않도록 둔다(F16 계열).
func (s *Server) seedFindingWorkflowTools() {
	const hostSearchDescriptionFlag = "finding_workflow_tools_v3_host_search_description"
	if value, _, _ := s.m.pg.GetSetting(hostSearchDescriptionFlag); value != "true" {
		// Only replace the original built-in text. A user-edited description is
		// authoritative and must survive upgrades.
		legacy := "The query records the target traffic that the agent has crawled (must specify a host, which can be filtered by URL substring or body keyword). body_contains does a full-text search of the crawled request/response header and body, supports any substring and Chinese (at least 3 characters), and can be used to find passwords, keys, errors, intranet addresses in response, etc. Returns only Extremely Lightweight Index (resp_len) and does not contain any response content.From ); look at the original request/response of a certain article with traffic_get(id). Look back at the access to the resource, find the endpoint first, and use it to avoid repeating curls the same URL."
		if _, err := s.m.pg.Exec(`UPDATE tools SET description=$1,updated_at=now() WHERE key='traffic_search' AND system AND description=$2`, traffic.TrafficSearchDescription, legacy); err != nil {
			// Log and leave the flag unset so the next startup retries; do not
			// return, or a transient error here would also skip the reporter
			// migration below — the two are independent.
			log.Printf("[evidence] upgrade traffic_search description: %v", err)
		} else {
			_ = s.m.pg.SetSetting(hostSearchDescriptionFlag, "true")
		}
	}
	const flag = "finding_workflow_tools_v2_reporter"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	for _, key := range []string{"report_finding", "add_hint", "add_task_hint"} {
		row, err := s.m.pg.GetTool(key)
		if err != nil {
			log.Printf("[evidence] load %s: %v", key, err)
			return
		}
		if row == nil || !row.System {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			log.Printf("[evidence] invalid schema for %s: %v", key, err)
			return
		}
		if schema == nil {
			log.Printf("[evidence] missing object schema for %s", key)
			return
		}
		props := objectProperty(schema, "properties")
		if key == "report_finding" {
			if _, exists := props["evidence_hint_id"]; !exists {
				props["evidence_hint_id"] = map[string]any{"type": "integer", "description": "Optional: The hint ID of this vulnerability in this task; read traffic_refs saved traffic_refs and omit it when no prompts"}
			}
		} else {
			if _, exists := props["traffic_refs"]; !exists {
				props["traffic_refs"] = agent.HintTrafficSchema()
			}
			hints := objectProperty(props, "hints")
			if _, exists := hints["type"]; !exists {
				hints["type"] = "array"
			}
			items := objectProperty(hints, "items")
			if _, ok := items["type"]; !ok {
				items["type"] = "object"
			}
			itemProps := objectProperty(items, "properties")
			for name, value := range map[string]any{"text": strParam("Tips"), "asset_ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}}, "traffic_refs": agent.HintTrafficSchema()} {
				if _, exists := itemProps[name]; !exists {
					itemProps[name] = value
				}
			}
		}
		raw, _ := json.Marshal(schema)
		result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system AND schema=$3::jsonb`, key, string(raw), string(row.Schema))
		if err != nil {
			log.Printf("[evidence] upgrade %s: %v", key, err)
			return
		}
		if n, _ := result.RowsAffected(); n != 1 {
			return
		} // preserve concurrent user edits
	}
	// Upgrade only the original default binding. Customized lists and enabled
	// flags survive; the one-time flag also preserves future user unbinding.
	readers := `["worker","reporter"]`
	for _, key := range []string{"traffic_search", "traffic_get", "traffic_blob"} {
		if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$2::jsonb WHERE key=$1 AND system AND (agents='["worker"]'::jsonb OR (agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5))`, key, readers); err != nil {
			return
		}
	}
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents=$1::jsonb WHERE key='get_finding_traffic' AND system AND agents @> '["auto","reporter"]'::jsonb AND jsonb_array_length(agents)=2`, `["auto","reporter","worker","planner","mainagent","pentest"]`); err != nil {
		return
	}
	// Replace the previous code default only; preserve customized binding lists.
	if _, err := s.m.pg.Exec(`UPDATE tools SET agents='["reporter"]'::jsonb WHERE key='bind_finding_traffic' AND system AND agents @> '["worker","planner","mainagent","auto","pentest"]'::jsonb AND jsonb_array_length(agents)=5`); err != nil {
		return
	}
	if err := s.m.pg.AddAgentToToolBinding("reporter", []string{"bind_finding_traffic"}); err != nil {
		return
	}
	_ = s.m.pg.SetSetting(flag, "true")
}

func objectProperty(parent map[string]any, key string) map[string]any {
	value, ok := parent[key].(map[string]any)
	if !ok {
		value = map[string]any{}
		parent[key] = value
	}
	return value
}

func (s *Server) agentFindingTrafficAccess(ctx context.Context, id int64, write bool) error {
	if id <= 0 {
		return errors.New("finding_id must be a record ID for a standalone vulnerability; not an exploratory node ID")
	}
	f, err := s.m.pg.GetFinding(id)
	if err != nil {
		return err
	}
	if f == nil {
		return fmt.Errorf("%w : finding_id = %d . The evidence tool uses a separate vulnerability to record IDs, read from list_task_findingsget_task_node_detailfinding_id field of list_task_node_detail; do not pass id / finding_node_id", db.ErrFindingNotFound, id)
	}
	if ri := agent.RunInfoFrom(ctx); ri.TaskID > 0 {
		task := s.m.ResolveTask(strconv.FormatInt(ri.TaskID, 10))
		if task == nil {
			return errors.New("The task does not exist.")
		}
		_, inherited, allowed := findingProvenanceInTask(task, f.TaskID)
		if !allowed {
			return errors.New("The vulnerability cannot be read by the current task")
		}
		if write && inherited {
			return errors.New("Inherited traffic evidence of the vulnerability read-only, please modify the source task")
		}
	}
	return nil
}

func (s *Server) toolBindFindingTraffic() actool.CoreTool {
	return wrTool("bind_finding_traffic", "finding_id uses independent vulnerability to record IDs; do not pass exploratory node IDs. All references in the same batch are successful or all failed, and repeated references do not overwrite existing instructions. Replenishment makes the existing report markup to be updated; do not re-explore or create a vulnerability for the fill package.",
		objSchema(map[string]any{"finding_id": strParam("Separate vulnerability record ID read from finding_id field of list_task_findings / get_task_node_detail"), "traffic_refs": agent.HintTrafficSchema()}, "finding_id", "traffic_refs"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			if !s.m.pg.GetBool(settingAgentTrafficBinding, false) {
				return actool.Errorf("Agent auto-binding traffic is turned off; open in system settings, or manually bind the page."), nil
			}
			var args struct {
				FindingID json.RawMessage `json:"finding_id"`
				Refs      []db.TrafficRef `json:"traffic_refs"`
			}
			if err := json.Unmarshal(raw, &args); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			id := parseProfileID(args.FindingID)
			if err := s.agentFindingTrafficAccess(ctx, id, true); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(args.Refs) == 0 {
				return actool.Errorf("Replenishing requires at least one verified traffic_refstraffic_refs; no traffic required to call this tool"), nil
			}
			list, err := s.evidenceStore().Bind(ctx, id, args.Refs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(trafficSummary(list))
		})
}
