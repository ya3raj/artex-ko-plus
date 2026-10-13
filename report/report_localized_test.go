package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
)

// containsHan 은 문자열에 CJK 한자(중국어)가 섞여 있으면 true 를 돌려준다.
// 한글(unicode.Latin)·영문·숫자·기호는 한자가 아니므로 걸리지 않는다.
func containsHan(s string) (rune, bool) {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return r, true
		}
	}
	return 0, false
}

func sampleFindingNode(t *testing.T) *db.Node {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"vulnclass": "SQL Injection",
		"name":      "로그인 폼 SQL 주입",
		"severity":  "high",
		"summary":   "로그인 파라미터에서 오류 기반 SQL 주입이 확인되었습니다.",
		"evidence":  map[string]string{"poc": "' OR '1'='1"},
	})
	if err != nil {
		t.Fatalf("payload 직렬화 실패: %v", err)
	}
	return &db.Node{ID: 1, Kind: "finding", Payload: payload}
}

func sampleDBFinding() *db.DBFinding {
	return &db.DBFinding{
		ID:              123,
		VulnClass:       "SQL Injection",
		Name:            "로그인 폼 SQL 주입",
		Severity:        "high",
		Summary:         "로그인 파라미터에서 오류 기반 SQL 주입이 확인되었습니다.",
		Evidence:        "' OR '1'='1",
		Status:          "confirmed",
		Report:          "상세 분석 본문.",
		CreatedAt:       time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		EvidenceVersion: 2,
		TaskDescription: "데모 대상 침투 테스트",
		TrafficBindings: []db.FindingTrafficBinding{
			{
				ID:   9,
				Role: "request",
				Note: "주입 페이로드 전송 지점",
				Snapshot: db.TrafficEvidenceSnapshot{
					Method: "POST",
					URL:    "https://sandbox.local/login",
					Status: 200,
				},
			},
		},
	}
}

// TestReportMarkdownLocalized 는 탐색 그래프 보고서(report.Markdown)의 골격이 한국어이고
// 중국어 한자가 전혀 없음을 검증한다.
func TestReportMarkdownLocalized(t *testing.T) {
	out := Markdown(Input{
		Title:       "데모 작업",
		Goal:        "샌드박스 전수 점검",
		GeneratedAt: time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC),
		AssetCounts: map[string]int{"host": 2, "url": 5},
		Findings:    []*db.Node{sampleFindingNode(t)},
	})
	if r, ok := containsHan(out); ok {
		t.Fatalf("보고서 골격에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# Penetration Test Report: 데모 작업",
		"- **Task objective**: 샌드박스 전수 점검",
		"- **Generated at**:",
		"## Summary",
		"- Confirmed findings: **1**",
		"## Findings",
		"**PoC / Evidence:**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("보고서 골격에 %q 가 없다", want)
		}
	}
}

// TestReportMarkdownEmptyLocalized 는 취약점이 없을 때의 안내 문구가 한국어임을 검증한다.
func TestReportMarkdownEmptyLocalized(t *testing.T) {
	out := Markdown(Input{Title: "빈 작업", GeneratedAt: time.Now()})
	if r, ok := containsHan(out); ok {
		t.Fatalf("빈 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	if !strings.Contains(out, "_No vulnerabilities were confirmed in this run._") {
		t.Errorf("빈 보고서 안내 문구가 한국어가 아니다:\n%s", out)
	}
}

// TestFindingsMarkdownLocalized 는 취약점 요약/상세 Markdown 익스포트 골격과 심각도 라벨이
// 한국어이고 중국어 한자가 없음을 검증한다.
func TestFindingsMarkdownLocalized(t *testing.T) {
	f := sampleDBFinding()
	out := FindingsMarkdown([]*db.DBFinding{f}, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC))
	if r, ok := containsHan(out); ok {
		t.Fatalf("취약점 요약 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), out)
	}
	for _, want := range []string{
		"# Findings summary report",
		"- **Generated at**:",
		"- **Total findings**: 1",
		"## Summary",
		"| Severity | Count |",
		"| Critical |", "| High |", "| Medium |", "| Low |", // 심각도 라벨(UI status.severity 와 동일)
		"## Finding details",
		"- **Type**: SQL Injection",
		"- **Status**: confirmed",
		"- **Task**: 데모 대상 침투 테스트",
		"- **Discovered at**:",
		"**Evidence:**",
		"**Detailed report:**",
		"## Related traffic evidence",
		"Evidence version: 2, number of bindings: 1.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("요약 보고서에 %q 가 없다", want)
		}
	}

	single := SingleFindingMarkdown(f, time.Date(2026, 10, 4, 2, 30, 0, 0, time.UTC))
	if r, ok := containsHan(single); ok {
		t.Fatalf("단건 보고서에 중국어 한자 %q 가 남아 있다:\n%s", string(r), single)
	}
	for _, want := range []string{
		"- **Severity**: high",
		"## Overview",
		"## Evidence",
		"## Detailed report",
		"[Request](evidence/123/9/request.http)",
		"[Response](evidence/123/9/response.http)",
	} {
		if !strings.Contains(single, want) {
			t.Errorf("단건 보고서에 %q 가 없다", want)
		}
	}
}

// TestFindingsCSVLocalized 는 CSV 익스포트 헤더가 한국어이고 중국어 한자가 없음을 검증한다.
// (BOM 뒤 헤더 행만 한국어면 된다. 데이터 값은 원본 그대로 둔다.)
func TestFindingsCSVLocalized(t *testing.T) {
	raw := FindingsCSV([]*db.DBFinding{sampleDBFinding()})
	out := strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
	header := strings.SplitN(out, "\n", 2)[0]
	if r, ok := containsHan(header); ok {
		t.Fatalf("CSV 헤더에 중국어 한자 %q 가 남아 있다: %s", string(r), header)
	}
	for _, col := range []string{"ID", "Name", "Type", "Severity", "Status", "Task", "Discovered at", "Overview", "Traffic evidence count", "Traffic evidence IDs"} {
		if !strings.Contains(header, col) {
			t.Errorf("CSV 헤더에 %q 열이 없다: %s", col, header)
		}
	}
}
